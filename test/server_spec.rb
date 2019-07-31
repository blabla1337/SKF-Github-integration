require 'test_helper'

include Rack::Test::Methods

def app
  GHAapp.new
end

describe 'App' do
  it 'should have a root' do
    payload = {
      action: "labeled",
      label: {
        name: "SKF"
      },
      repository: {
        full_name: "awesome_user/awesome_test_repository"
      },
      issue: {
        number: 1337
      }
    }
    header "X-GITHUB-EVENT", "issues"
    post '/', payload.to_json
    assert last_response.ok?
  end
end

