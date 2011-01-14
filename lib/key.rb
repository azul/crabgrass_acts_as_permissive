module ActsAsPermissive
  class Key < ActiveRecord::Base
    belongs_to :locked, :polymorphic => true

    named_scope :for_user, lambda { |user|
      { :conditions => "keyring_code IN (#{user.access_codes.join(", ")})" }
    }

    named_scope :for_holder, lambda { |holder|
      { :conditions => access_conditions_for(holder) }
    }

    def self.access_conditions_for(holder)
      case holder
      when User
        "keyring_code IN (#{holder.access_codes.join(", ")})"
      when :public, :all
        {:keyring_code => 1}
      when UnauthenticatedUser
        {:keyring_code => 1}
      when nil
        {:keyring_code => 1}
      else
        {:keyring_code => holder.entity_code}
      end
    end

    named_scope :for_public, :conditions => {:holder_code => 0}

    def allow!(locks, options = {})
      if options[:reset]
        self.mask = bits_for_locks(locks)
      else
        self.mask |= bits_for_locks(locks)
      end
      save
    end

    def disallow!(locks)
      self.mask &= ~bits_for_locks(locks)
      save
    end

    def bits_for_locks(locks)
      self.object.class.bits_for_locks(locks)
    end

    def locks(options={})
      klass = self.object.class
      if options[:disabled]
        locks = klass.locks_for_bits(~self.mask)
      else
        locks = klass.locks_for_bits(self.mask)
      end
      postfix = klass.name.underscore
      if options[:with_class]
        locks.map{|l| (l.to_s + '_' + postfix).to_sym}
      elsif options[:select_options]
        locks.map{|l| [(l.to_s + '_' + postfix).to_sym, klass.bits_for_locks(l)]}
      else
        locks
      end
    end

    def holder_type
      case self.keyring_code.to_s
      when "0"
        :public
      else
        raise ActsAsPermissive::PermissionError.new "unknown entity code: #{self.entity_code}"
      end
    end

    def holder
      case self.keyring_code.to_s
      when "0"
        :public
      else
        raise ActsAsPermissive::PermissionError.new "unknown entity code: #{self.entity_code}"
      end
    end

    def self.code_for_holder(holder)
      holder = holder.to_sym if holder.is_a? String
      case older
      when :all,:public
        0
      when Symbol
        raise ActsAsPermissive::PermissionError.new("ActsAsPermissive: Entity alias '#{entity}' is unknown.")
      else
        code = entity.entity_code.to_i
      end
    end
  end
end
