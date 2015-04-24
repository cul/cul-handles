require 'rubygems'
require 'test/unit'
require 'shoulda'
require 'yaml'

require 'simplecov'
SimpleCov.start do
  coverage_dir 'tmp/coverage'
  add_group "Library", "lib"
  add_filter "test"
end

$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '..', 'lib'))
$LOAD_PATH.unshift(File.dirname(__FILE__))

require 'cul-handles'

class Test::Unit::TestCase

end