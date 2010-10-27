require 'activesupport'

class Permission < ActiveRecord::Base
  belongs_to :object, :polymorphic => true

  def self.bits_for_keys(keys)
    keys = [keys] unless keys.is_a? Array
    keys.inject(0) {|any, key| any | bit_for(key)}
  end

  def self.bit_for(key)
    ActsAsPermissive::Permissions.hash[key.to_s.downcase.to_sym] || 0
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
            not_allowed = Permission.bits_for_keys(keys) & ~bitmask
            not_allowed == 0
          end

          def allow!(entity, keys, options = {})
            permission = permissions.find_or_initialize_by_entity_code(entity.entity_code)
            if options[:reset]
              permission.mask = Permission.bits_for_keys(keys)
            else
              permission.mask |= Permission.bits_for_keys(keys)
            end
            permission.save!
          end

          def disallow!(entity, keys)
            permission = permissions.find_or_initialize_by_entity_code(entity.entity_code)
            permission.mask &= ~Permission.bits_for_keys(keys)
            permission.save!
          end

          protected

            def bitmask
              current_user_permission_set.or_mask.to_i
            end
        end
      end
    end
  end

  module Permissions
    def self.const_set(*args)
      @@hash = nil
      super
    end

    def self.hash
      @@hash ||= begin
        bitwise_hash = constants.inject({}) do |hash, constant_name|
          hash[constant_name.downcase] = 2 ** ActsAsPermissive::Permissions.const_get(constant_name.to_sym)
          hash
        end
        inverted_hash = bitwise_hash.invert
        bitwise_hash.values.sort.inject(ActiveSupport::OrderedHash.new) do |hash, value|
          hash[inverted_hash[value].to_sym] = value
          hash
        end
      rescue ArgumentError
        raise StandartError.new("Permissions must be integers or longs.")
       end
    end
  end
end
