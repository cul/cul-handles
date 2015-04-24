require 'rubygems'
require 'rake'

require 'rake/testtask'

Rake::TestTask.new(:test) do |test|
  test.libs << 'lib' << 'test'
  test.pattern = 'test/*_test.rb'
  test.verbose = true
end
Rake::TestTask.new(:unit_test) do |test|
  test.libs << 'lib' << 'test'
  test.pattern = 'test/unit/**/*_test.rb'
  test.verbose = true
end
Rake::TestTask.new(:system_test) do |test|
  test.libs << 'lib' << 'test'
  test.pattern = 'test/system/**/*_test.rb'
  test.verbose = true
end

task :test

task :ci => [:test, :unit_test]

task :default => :ci

require 'rdoc/task'
Rake::RDocTask.new do |rdoc|
  if File.exist?('VERSION')
    version = File.read('VERSION')
  else
    version = ""
  end

  rdoc.rdoc_dir = 'rdoc'
  rdoc.title = "cul-handles #{version}"
  rdoc.rdoc_files.include('README*')
  rdoc.rdoc_files.include('lib/**/*.rb')
end
