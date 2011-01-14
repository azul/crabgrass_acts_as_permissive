require 'activesupport'

module ActsAsPermissive

  class PermissionError < StandardError; end;

  def self.included(base)
    base.class_eval do
      # This allows you to define permissions on the object that acts as permissive.
      # Permission resolution uses entity codes so that we can resolve permissions
      # via groups without joins

      def self.acts_as_permissive(*permissions)

        has_many :permissions, :as => :object do

          def allow?(keys, reload=false)
            self.reload if reload
            allowed = self.inject(0) {|any, permission| any | permission.mask}
            not_allowed = proxy_owner.class.bits_for_keys(keys) & ~allowed
            not_allowed == 0
          end
        end

        # let's use AR magic to cache permissions from the controller like this...
        # @pages = Page.find... :include => {:owner => :current_user_permissions}
        has_many :current_user_permissions,
          :class_name => "Permission",
          :conditions => 'entity_code IN (#{User.current.access_codes.join(", ")})',
          :as => :object do
          def allow?(keys)
            allowed = self.inject(0) {|any, permission| any | permission.mask}
            not_allowed = proxy_owner.class.bits_for_keys(keys) & ~allowed
            not_allowed == 0
          end
        end


        named_scope :with_access, lambda { |key, entity|
          { :joins => :permissions,
            :group => 'object_id, object_type',
            :conditions => Permission.access_conditions_for(entity) }
        }

        class_eval do

          def has_access!(key, user)
            if has_access?(key, user)
              return true
            else
              # TODO: make the error message flexible and meaningful
              raise PermissionDenied.new(I18n.t(:permission_denied))
            end
          end

          def has_access?(key, entity = User.current)
            if entity == User.current
              # these might be cached through AR.
              current_user_permissions.allow?(key)
            else
              # the named scope might have changed so we need to reload.
              permissions.for_entity(entity).allow?(key, true)
            end
          end

          def public_permissions=(hash)
            code = 1
            permission = permissions.find_or_initialize_by_entity_code(code)
            allow = hash.select{|k,v| v!=0}
            disallow = hash.select{|k,v| v==0}
            permission.allow! allow.map(&:first)
            permission.disallow! disallow.map(&:first)
          end

          def allow!(*args)
            ActsAsPermissive::Permissions.get_entities_from_args(*args) do |entity, keys, options|
              code = Permission.code_for_entity(entity)
              permission = permissions.find_or_initialize_by_entity_code(code)
              permission.allow! keys, options || {}
            end
          end

          def disallow!(*args)
            ActsAsPermissive::Permissions.get_entities_from_args(*args) do |entity, keys, options|
              code = Permission.code_for_entity(entity)
              permission = permissions.find_by_entity_code(code)
              permission.disallow!(keys) if permission
            end
          end

          def accessors_by_action
            permissions.inject({}) do |hash, perm|
              perm.actions.each do |action|
                hash[action] ||= []
                hash[action].push perm.accessors
              end
            end
          end



          protected


          def self.bits_for_keys(keys)
            return ~0 if keys == :all
            keys = [keys] unless keys.is_a? Array
            keys.inject(0) {|any, key| any | self.bit_for(key)}
          end

          def self.keys_for_bits(bits)
            ActsAsPermissive::Permissions.keys_for(self, bits)
          end

          def self.bit_for(key)
            ActsAsPermissive::Permissions.bit_for(self, key)
          end

          def self.add_permissions(*keys)
            keys = keys.first if keys.first.is_a? Enumerable
            ActsAsPermissive::Permissions.add_bits(self.name, keys)
          end
        end
        if permissions.any?
          self.add_permissions(*permissions)
        end
      end

    end
  end

  module Permissions

    def self.add_bits(class_name, keys)
      @@hash ||= {}
      class_hash = @@hash[class_name] ||= {}
      if keys.is_a? Hash
        keys.reject!{|k,v| class_hash.keys.include? k}
      elsif keys.is_a? Enumerable
        keys.reject!{|k| class_hash.keys.include? k}
      end
      class_hash.merge! build_bit_hash(keys, @@hash[class_name].count)
    end

    def self.bit_for(klass, key)
      bit = @@hash[key_for_class(klass)][key.to_s.downcase.to_sym]
      if bit.nil?
        raise ActsAsPermissive::PermissionError.new("Permission '#{key}' is unknown to class '#{klass.name}'")
      else
        bit
      end
    end

    def self.keys_for(klass, bits)
      hash = @@hash[key_for_class(klass)]
      array = hash.map{|k,b| k if (bits & b) != 0}
      array.compact
    end

    def self.get_entities_from_args(*args)
      if args[0].is_a? Hash
        args[0].each_pair do |key, entities|
          entities = [entities] unless entities.is_a? Array
          entities.each do |entity|
            yield entity, key, args[1]
          end
        end
      else
        yield *args
      end
    end


    protected
    def self.build_bit_hash(keys, offset)
      bitwise_hash = {}
      if keys.is_a? Hash
        keys.each do |key, value|
          bitwise_hash[key] = 2 ** value
        end
      elsif keys.is_a? Enumerable
        keys.each_with_index do |key, index|
          bitwise_hash[key] = 2 ** (index + offset)
        end
      end
      bitwise_hash
    rescue ArgumentError
      raise ActsAsPermissive::PermissionError.new("Permission bits must be integers or longs.")
    end

    def self.key_for_class(klass)
      current=klass
      until @@hash.keys.include?(current.name) do
        current = current.superclass
        if current.nil?
          raise ActsAsPermissive::PermissionError.new("Class #{klass} not registered with acts_as_permissive.")
        end
      end
      current.name
    end
  end
end
