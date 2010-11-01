require 'activesupport'

class Permission < ActiveRecord::Base
  belongs_to :object, :polymorphic => true

  def allows?(keys)
    not_allowed = bits_for_keys(keys) & ~bitmask
    not_allowed == 0
  end

  def allow!(keys, options = {})
    if options[:reset]
      self.mask = bits_for_keys(keys)
    else
      self.mask |= bits_for_keys(keys)
    end
    save!
  end

  def disallow!(keys)
    self.mask &= ~bits_for_keys(keys)
    save!
  end

  protected

  # we add an or_mask to the permissions when getting the
  # current_user_permission_set. This contains all permissions the
  # user has through different groups. If it's there - use it.
  def bitmask
    self.respond_to?(:or_mask) ?
      or_mask.to_i :
      mask
  end

  def bits_for_keys(keys)
    keys = [keys] unless keys.is_a? Array
    keys.inject(0) {|any, key| any | object.class.bit_for(key)}
  end

end

module ActsAsPermissive
  def self.included(base)
    base.class_eval do
      # This allows you to define permissions on the object that acts as permissive.
      # Permission resolution uses entity codes so that we can resolve permissions
      # via groups without joins

      def self.acts_as_permissive(options = {})
        has_many :permissions, :as => :object
        # let's use AR magic to cache permissions from the controller like this...
        # @pages = Page.find... :include => {:owner => :current_user_permission_set}
        has_one :current_user_permission_set,
          :class_name => "Permission",
          :as => :object,
          :select => '*, BIT_OR(mask) as or_mask',
          :conditions => 'entity_code IN (#{User.current.entity_access_cache.join(", ")})'

        class_eval do
          def allows?(keys)
            current_user_permission_set.allows?(keys)
          end

          def allow!(entity, keys, options = {})
            permission = permissions.find_or_initialize_by_entity_code(entity.entity_code)
            permission.allow! keys, options
          end

          def disallow!(entity, keys)
            permission = permissions.find_or_initialize_by_entity_code(entity.entity_code)
            permission.disallow! keys
          end

          def self.bit_for(key)
            ActsAsPermissive::Permissions.bit_for(self.name, key)
          end

          def self.permission_keys=(keys)
            ActsAsPermissive::Permissions.set_bits(self.name, keys)
          end
        end
        if options[:keys]
          self.permission_keys = options[:keys]
        end
      end
    end
  end

  module Permissions

    def self.set_bits(class_name, keys)
      @@hash ||= {}
      @@hash[class_name] = build_bit_hash(keys)
    end

    def self.bit_for(class_name, key)
      @@hash[class_name][key.to_s.downcase.to_sym] || 0
    end

    protected
    def self.build_bit_hash(keys)
      bitwise_hash = {}
      if keys.is_a? Array
        keys.each_with_index do |key, index|
          bitwise_hash[key] = 2 ** index
        end
      elsif keys.is_a? Hash
        keys.each do |key, value|
          bitwise_hash[key] = 2 ** value
        end
      end
      bitwise_hash
    rescue ArgumentError
      raise StandartError.new("Permissions must be integers or longs.")
    end
  end
end
