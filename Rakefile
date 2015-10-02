require "bundler/gem_tasks"
require "rspec/core/rake_task"

desc "Display LOC stats"
task :stats do
  puts "\n## Production Code Stats"
  sh "countloc -r lib"
end

require "finstyle"
require "rubocop/rake_task"
RuboCop::RakeTask.new(:style) do |task|
  task.options << "--display-cop-names"
end

desc "Run RSpec unit tests"
RSpec::Core::RakeTask.new(:spec)

desc "Run all quality tasks"
task :quality => [:stats, :spec, :style]

task :default => [:quality]
