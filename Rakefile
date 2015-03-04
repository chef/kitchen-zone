require "bundler/gem_tasks"
require 'cane/rake_task'
require 'tailor/rake_task'
require 'rspec/core/rake_task'

desc "Run cane to check quality metrics"
Cane::RakeTask.new do |cane|
  cane.canefile = './.cane'
end

Tailor::RakeTask.new

desc "Display LOC stats"
task :stats do
  puts "\n## Production Code Stats"
  sh "countloc -r lib"
end

desc 'Run RSpec unit tests'
RSpec::Core::RakeTask.new(:spec)

desc "Run all quality tasks"
task :quality => [:cane, :tailor, :stats, :spec]

task :default => [:quality]
