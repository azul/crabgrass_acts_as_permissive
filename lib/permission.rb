module ActsAsPermissive
  class Permission < ActiveRecord::Base
    belongs_to :permissive, :polymorphic => true

    named_scope :for_user, lambda { |user|
      { :conditions => "entity_code IN (#{user.access_codes.join(", ")})" }
    }

    named_scope :for_entity, lambda { |entity|
      { :conditions => access_conditions_for(entity) }
    }

    def self.access_conditions_for(entity)
      case entity
      when User
        "entity_code IN (#{entity.access_codes.join(", ")})"
      when :public, :all
        {:entity_code => 1}
      when UnauthenticatedUser
        {:entity_code => 1}
      when nil
        {:entity_code => 1}
      else
        {:entity_code => entity.entity_code}
      end
    end

    named_scope :for_public, :conditions => {:entity_code => 1}

    def allow!(keys, options = {})
      if options[:reset]
        self.mask = bits_for_keys(keys)
      else
        self.mask |= bits_for_keys(keys)
      end
      save
    end

    def disallow!(keys)
      self.mask &= ~bits_for_keys(keys)
      save
    end

    def bits_for_keys(keys)
      self.object.class.bits_for_keys(keys)
    end

    def actions(options={})
      klass = self.object.class
      if options[:disabled]
        actions = klass.keys_for_bits(~self.mask)
      else
        actions = klass.keys_for_bits(self.mask)
      end
      postfix = klass.name.underscore
      if options[:with_class]
        actions.map{|a| (a.to_s + '_' + postfix).to_sym}
      elsif options[:select_options]
        actions.map{|a| [(a.to_s + '_' + postfix).to_sym, klass.bits_for_keys(a)]}
      else
        actions
      end
    end

    def accessor_type
      case self.entity_code.to_s
      when "1"
        :public
      when /^1\d+/
        :user
      when /^7\d+/
        :friends
      when /^8\d+/
        :group
      when /^9\d+/
        :peers
      else
        raise ActsAsPermissive::PermissionError.new "unknown entity code: #{self.entity_code}"
      end
    end

    def accessors
      case self.entity_code.to_s
      when "1"
        :public
      when /^1(\d+)/
        User.find($1)
      when /^7(\d+)/
        :friends
      when /^8(\d+)/
        Group.find($1)
      when /^9(\d+)/
        :peers
      else
        raise ActsAsPermissive::PermissionError.new "unknown entity code: #{self.entity_code}"
      end
    end

    def self.code_for_entity(entity)
      entity = entity.to_sym if entity.is_a? String
      case entity
      when :all,:public
        1
      when :friends
        self.friends.entity_code.to_i
      when :peers
        self.peers.entity_code.to_i
      when :self, :members
        self.entity_code.to_i
      when Symbol
        raise ActsAsPermissive::PermissionError.new("ActsAsPermissive: Entity alias '#{entity}' is unknown.")
      else
        code = entity.entity_code.to_i
      end
    end
  end
end
