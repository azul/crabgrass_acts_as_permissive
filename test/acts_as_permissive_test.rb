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
    create_table :societies
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

  def access_codes
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
  alias_method :entity_code, :id
  # let's define the different permissions
  acts_as_permissive :see, :see_groups, :pester, :burdon, :spy
end

# some permissive class with other keys
class Society < ActiveRecord::Base
  acts_as_permissive :publish, :play, :sing
end

##
## TEST
##

setup_db

class ActsAsPermissiveTest < Test::Unit::TestCase

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

  def test_permission_functions
    @fusion.allow! @soul, :burdon
    @fusion.allow! @jazz, [:pester, :spy, :see]
    assert @fusion.has_access?(:pester), "fusion should allow me to pester as I am a jazz member."
    assert !@fusion.has_access?(:burdon), "fusion should not allow me to burdon as I am not a soul member."
    # I'm a soul member now
    @soul.users << @me
    @me.reload
    @fusion.reload
    assert @fusion.has_access?([:burdon, :spy, :see]), "combining access from different entities should work."
  end

  def test_getting_permissions_per_action
    @fusion.allow! @soul, [:burdon, :spy]
    @fusion.allow! @jazz, [:pester, :see, :burdon]
    assert_equal @fusion.accessors_by_action, {
      :burdon => [@soul, @jazz],
      :pester => @jazz,
      :spy => @soul,
      :see => @jazz}
  end

  def test_setting_permissions_per_action
    @fusion.allow! @soul, :spy
    @fusion.allow! :burdon => [@soul, @jazz],
      :pester => @jazz,
      :see => @jazz
    assert @fusion.has_access?(:pester), "fusion should allow me to pester as I am a jazz member."
    assert !@fusion.has_access?(:spy), "fusion should not allow me to spy as I am not a soul member."
    # I'm a soul member now
    @soul.users << @me
    @me.reload
    @fusion.reload
    assert @fusion.has_access?([:burdon, :spy, :see]), "combining access from different entities should work."
  end


  def test_keys_in_different_class
    @brave_new = Society.create!
    @brave_new.allow! @jazz, :publish
    assert @brave_new.has_access?(:publish), "the publish key should work for society"
    assert_raises ActsAsPermissive::PermissionError do
      @brave_new.allow! @jazz, :see
    end
    assert_raises ActsAsPermissive::PermissionError do
      @soul.allow! @jazz, :publish
    end
  end

  def test_query_caching
    # all @jazz users may see @jazz's groups
    @jazz.allow! @jazz, :see
    pages = Page.find :all, :include => {:owner => :current_user_permissions}
    # we remove the permission but it has already been cached...
    assert @jazz.has_access?(:see), ":see should be allowed to current_user."
    @jazz.disallow!(@jazz, :see)
    @jazz.reload
    assert !@jazz.has_access?(:see), "the :see permission should have been revoked."
    assert_equal @miles, pages.first
    assert pages.first.owner.has_access?(:see), "pages should have cached the permission."
  end

  module ActsAsPermissive::Permissions
    DO_CRAZY_THINGS = 8
  end

  def test_adding_symbols
    assert_raises ActsAsPermissive::PermissionError do
      @jazz.allow! @jazz, :do_crazy_things
    end
    Entity.add_permissions :do_crazy_things
    @jazz.allow! @jazz, :do_crazy_things
    assert @jazz.has_access?(:do_crazy_things), "I should be able to add keys in different places"
    @jazz.allow! @jazz, :see
    @jazz.reload
    assert @jazz.has_access?(:see), "Old keys should still work after adding new ones."
  end



  ## INTERNALS
  #
  #  tests that access internal structures of the implementation
  #  Please use the functions called in the tests above instead.
  #

  def test_bit_mask
    @fusion.allow! @soul, :burdon
    p = @fusion.permissions.find_by_entity_code(@soul.entity_code)
    assert_equal 8, p.mask
    p = @fusion.allow! @jazz, [:pester, :spy, :see]
    p = @fusion.permissions.find_by_entity_code(@jazz.entity_code)
    assert_equal 21, p.mask
  end

end

