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
    stub_request(:post, "https://api.github.com/app/installations/access_tokens").
      with(body: "{}").to_return(
        status: 200,
        body: '{"token": "secret_bearer_token"}',
        headers: {"Content-Type" => "application/json; charset=utf-8"}
      )
    stub_request(:post, "https://api.github.com/repos/awesome_user/awesome_test_repository/issues/1337/comments").
      with(body: /\{"body":"Click here to set up your SKF security controls: https:\/\/skftest\.localhost\/something\?token=[^"]+"\}/).
      to_return(status: 200, body: "", headers: {})
    post '/', payload.to_json
    assert last_response.ok?
  end
end

