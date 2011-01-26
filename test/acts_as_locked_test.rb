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
  :database => "test_acts_as_locked"
)

# log db activity:
# ActiveRecord::Base.logger = Logger.new(STDOUT)

##
## DEFINE DB
##

def setup_db
  teardown_db
  ActiveRecord::Schema.define(:version => 1) do
    create_table :keys do |p|
      p.integer :mask, :default => 0
      p.integer :locked_id
      p.string :locked_type
      p.integer :keyring_code
    end
    create_table :styles do |t|
      t.column :name, :string
    end
    create_table :users do |t|
      t.column :name, :string
    end
    create_table :styles_users, :id => false do |t|
      t.integer :style_id
      t.integer :user_id
    end
    create_table :artists do |t|
      t.column :name, :string
      t.column :main_style_id, :integer
    end
    create_table :artists_styles, :id => false do |t|
      t.column :artist_id, :integer
      t.column :style_id, :integer
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
    ActiveRecord::Base.connection.execute("DELETE FROM `#{table}`;")
  end
end

##
## DEFINE MODELS
##

class User < ActiveRecord::Base
  has_and_belongs_to_many :styles
  def self.current
    @current
  end
  def self.current=(value)
    @current = value
  end

  def access_codes
    self.styles.map(&:id)
  end
end

class Artist < ActiveRecord::Base
  belongs_to :main_style, :class_name => "Style"
  has_and_belongs_to_many :styles
  def keyring_code; 100 + id; end
end

class Style < ActiveRecord::Base
  has_and_belongs_to_many :artists
  has_and_belongs_to_many :users
  alias_method :keyring_code, :id
  # let's define the different locks
  acts_as_locked :see, :hear, :dance
  ActsAsLocked::Key.resolve_holder :style
end

# some locked class with other keys
class Society < ActiveRecord::Base
  acts_as_locked :publish, :play, :sing
end

##
## TEST
##

setup_db

class ActsAsLockedTest < Test::Unit::TestCase

  def setup
    @fusion = Style.create! :name => "fusion"
    @jazz = Style.create! :name => "jazz"
    @soul = Style.create! :name => "soul"
    @miles = Artist.create! :name => "Miles", :main_style => @jazz
    @jazz.artists << @miles
    @fusion.artists << @miles
    @ella = @jazz.artists.create! :name => "Ella", :main_style => @jazz
    @soul.artists << @ella
    @chick = @fusion.artists.create! :name => "Chick", :main_style => @fusion
    @me = @jazz.users.create! :name => 'me'
    # login
    User.current = @me
  end

  def teardown
    reset_db
  end

  def test_key_functions
    @fusion.grant! @soul, :dance
    @fusion.grant! @jazz, [:hear, :see]
    assert @fusion.has_access?(:hear), "fusion should allow me to hear as I am a jazz user."
    assert !@fusion.has_access?(:dance), "fusion should not allow me to dance as I am not a soul user."
    # I'm a soul user now
    @soul.users << @me
    @me.reload
    @fusion.reload
    assert @fusion.has_access?([:dance, :hear, :see]), "combining access from different holders should work."
  end

  def test_getting_holders_per_lock
    @fusion.grant! @soul, [:dance, :hear]
    @fusion.grant! @jazz, [:hear, :see]
    expected = {
      :hear => [@soul, @jazz],
      :see => [@jazz],
      :dance => [@soul]}
    assert_equal expected, @fusion.holders_by_lock
  end

  def test_setting_holders_per_lock
    @fusion.grant! @soul, :dance
    @fusion.grant! :hear => [@soul, @jazz],
      :see => @jazz
    assert @fusion.has_access?(:hear), "fusion should allow me to pester as I am a jazz user."
    assert !@fusion.has_access?(:dance), "fusion should not allow me to spy as I am not a soul user."
    # I'm a soul user now
    @soul.users << @me
    @me.reload
    @fusion.reload
    assert @fusion.has_access?([:dance, :hear, :see]), "combining access from different holders should work."
  end

  def test_locks_in_different_class
    @brave_new = Society.create!
    @brave_new.grant! @jazz, :publish
    assert @brave_new.has_access?(:publish), "the publish key should work for society"
    assert_raises ActsAsLocked::LockError do
      @brave_new.grant! @jazz, :see
    end
    assert_raises ActsAsLocked::LockError do
      @soul.grant! @jazz, :publish
    end
  end

  def test_locks_with_different_holder_types
    ActsAsLocked::Key.resolve_holder do |code|
      code > 100 ?
        Artist.find(code -100) :
        Style.find(code)
    end
    @jazz.grant! @soul, :see
    @jazz.grant! @miles, [:see, :dance]
    expected = {
      :see => [@soul, @miles],
      :dance => [@miles]}
    assert_equal expected, @jazz.holders_by_lock
    ActsAsLocked::Key.resolve_holder :style
  end


  def test_locks_with_symbolic_holders
    ActsAsLocked::Key.symbol_codes = {
      :public => 500,
      :all => 500,
      :admin => 501,
      :other => 502
    }
    ActsAsLocked::Key.resolve_holder do |code|
      case code
      when 1...100
        Style.find(code)
      when 100...200
        Artist.find(code -100)
      when 500...510
        ActsAsLocked::Key.symbol_for(code)
      end
    end
    @jazz.grant! :admin, [:see, :dance]
    assert_raises ActsAsLocked::LockError do
      @jazz.grant! :foo, [:see, :dance]
    end
    @jazz.grant! @soul, :see
    @jazz.grant! @miles, :hear
    expected = {
      :see => [:admin, @soul],
      :dance => [:admin],
      :hear => [@miles]}
    assert_equal expected, @jazz.holders_by_lock
    ActsAsLocked::Key.resolve_holder :style
    ActsAsLocked::Key.symbol_codes = {}
  end

  def test_query_caching
    # all @jazz users may see @jazz
    @jazz.grant! @jazz, :see
    artists = Artist.find :all, :include => {:main_style => :current_user_keys}
    # we remove the permission but it has already been cached...
    assert @jazz.has_access?(:see), ":see should be allowed to current_user."
    @jazz.revoke!(@jazz, :see)
    @jazz.reload
    assert !@jazz.has_access?(:see), "the :see key should have been revoked."
    assert_equal @miles, artists.first
    assert artists.first.main_style.has_access?(:see), "artists should have cached the permission."
  end

  def test_adding_lock_symbols
    assert_raises ActsAsLocked::LockError do
      @jazz.grant! @jazz, :do_crazy_things
    end
    Style.add_locks :do_crazy_things
    @jazz.grant! @jazz, :do_crazy_things
    assert @jazz.has_access?(:do_crazy_things), "I should be able to add keys in different places"
    @jazz.grant! @jazz, :see
    @jazz.reload
    assert @jazz.has_access?([:see, :do_crazy_things]), "Old keys should work with new ones."
  end



  ## INTERNALS
  #
  #  tests that access internal structures of the implementation
  #  Please use the functions called in the tests above instead.
  #

  def test_bit_mask
    Style.add_locks :do_crazy_things
    @fusion.grant! @soul, :do_crazy_things
    k = @fusion.keys.find_by_keyring_code(@soul.keyring_code)
    assert_equal 8, k.mask
    p = @fusion.grant! @jazz, [:see, :dance, :do_crazy_things]
    p = @fusion.keys.find_by_keyring_code(@jazz.keyring_code)
    assert_equal 13, p.mask
  end

end

