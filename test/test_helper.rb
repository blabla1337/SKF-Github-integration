require "minitest/autorun"
require "minitest/spec"
require "minitest/reporters"
require "pry"

Minitest::Reporters.use!

ENV['RACK_ENV'] = 'test'
require 'rack/test'

require File.expand_path '../../server.rb', __FILE__
