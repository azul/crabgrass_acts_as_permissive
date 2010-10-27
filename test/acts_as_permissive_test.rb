require 'test/unit'
require 'rubygems'
require 'activerecord'
require 'activesupport'
require 'ruby_debug'
require 'logger'

require "#{File.dirname(__FILE__)}/../init"

ActiveRecord::Base.establish_connection(
  :adapter  => "mysql",
  :host     => "localhost",
  :username => "user",
  :password => "password",
  :database => "test_acts_as_permissive"
)

# log db activity:
# ActiveRecord::Base.logger = Logger.new(STDOUT)

##
## DEFINE DB
##

def setup_db
  teardown_db
  ActiveRecord::Schema.define(:version => 1) do
    create_table :permissions do |p|
      p.integer :mask, :default => 0
      p.integer :object_id
      p.string :object_type
      p.integer :entity_code
    end
    create_table :entities do |t|
      t.column :name, :string
    end
    create_table :users do |t|
      t.column :name, :string
    end
    create_table :entities_users, :id => false do |t|
      t.integer :entity_id
      t.integer :user_id
    end
    create_table :pages do |t|
      t.column :name, :string
      t.column :owner_id, :integer
    end
    create_table :entities_pages, :id => false do |t|
      t.column :entity_id, :integer
      t.column :page_id, :integer
    end
  end
end

def teardown_db
  ActiveRecord::Base.connection.tables.each do |table|
    ActiveRecord::Base.connection.drop_table(table)
  end
end

def reset_db
  ActiveRecord::Base.connection.tables.each do |table|
    ActiveRecord::Base.connection.execute("DELETE FROM #{table};")
  end
end

##
## DEFINE MODELS
##

class User < ActiveRecord::Base
  has_and_belongs_to_many :entities
  def self.current
    @current
  end
  def self.current=(value)
    @current = value
  end

  def entity_access_cache
    self.entities.map(&:id)
  end
end

class Page < ActiveRecord::Base
  belongs_to :owner, :class_name => "Entity"
  has_and_belongs_to_many :entities
end

class Entity < ActiveRecord::Base
  has_and_belongs_to_many :pages
  has_and_belongs_to_many :users
  acts_as_permissive
  alias_method :entity_code, :id
end

# let's define the different permissions
module ActsAsPermissive::Permissions
  SEE = 0
  SEE_GROUPS = 1
  PESTER = 2
  BURDON = 3
  SPY = 4
end

##
## TEST
##

setup_db

class ActsAsSiteLimitedTest < Test::Unit::TestCase

  def setup
    @fusion = Entity.create! :name => "fusion"
    @jazz = Entity.create! :name => "jazz"
    @soul = Entity.create! :name => "soul"
    @miles = Page.create! :name => "Miles", :owner => @jazz
    @jazz.pages << @miles
    @fusion.pages << @miles
    @ella = @jazz.pages.create! :name => "Ella", :owner => @jazz
    @soul.pages << @ella
    @chick = @fusion.pages.create! :name => "Chick", :owner => @fusion
    @me = @jazz.users.create! :name => 'me'
    # login
    User.current = @me
  end

  def teardown
    reset_db
  end

  def test_query_caching
    # all @jazz users may see @jazz's groups
    permission = @jazz.permissions.create :mask => 1, :entity_code => @jazz.id
    pages = Page.find :all, :include => {:owner => :current_user_permission_set}
    #brute force...
    assert_equal @miles, pages.first
    assert_equal "1", pages.first.owner.current_user_permission_set.or_mask
  end

  def test_bit_mask_works
    # all @jazz members may see @jazz's groups
    @jazz.permissions.create :mask => 2, :entity_code => @jazz.id
    # all @soul members may see @jazz
    @jazz.permissions.create :mask => 1, :entity_code => @soul.id
    # I'm a soul member
    @soul.users << @me
    pages = Page.find :all, :include => {:owner => :current_user_permission_set}
    assert_equal @miles, pages.first
    # now the bitwise and of 1 and 2 is 3
    assert_equal "3", pages.first.owner.current_user_permission_set.or_mask
    @jazz.permissions.create :mask => 7, :entity_code => @soul.id
    pages = Page.find :all, :include => {:owner => :current_user_permission_set}
    # we're not just adding things up bit_or(2, 7) = 7
    assert_equal "7", pages.first.owner.current_user_permission_set.or_mask
  end

  def test_permission_functions
    @fusion.allow! @soul, :burdon
    p = @fusion.permissions.find_by_entity_code(@soul.entity_code)
    assert_equal 8, p.mask
    p = @fusion.allow! @jazz, [:pester, :spy, :see]
    p = @fusion.permissions.find_by_entity_code(@jazz.entity_code)
    assert_equal 21, p.mask
    assert @fusion.allows? :pester
    assert !@fusion.allows?(:burdon)
    # I'm a soul member now
    @soul.users << @me
    @me.reload
    @fusion.reload
    assert @fusion.allows? [:burdon, :spy, :see]
  end
end

