require 'test_helper'

include Rack::Test::Methods

def app
  GHAapp.new
end

describe 'App' do
  it 'should listen for github events' do
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

  it 'should listen for SKF callbacks' do
    stub_request(:post, "https://api.github.com/app/installations/access_tokens").
      with(body: "{}").to_return(
        status: 200,
        body: '{"token": "secret_bearer_token"}',
        headers: {"Content-Type" => "application/json; charset=utf-8"}
      )
    stub_request(:post, "https://api.github.com/repos/awesome_user/awesome_test_repository/issues/1337/comments").
      with(body: "{\"body\":\"some controls:\\n- [ ] control 1\\n- [ ] control 2\"}").
      to_return(status: 200, body: "", headers: {})
    payload = {
      repo: "awesome_user/awesome_test_repository",
      issue_number: 1337,
      comment_text: "some controls:\n- [ ] control 1\n- [ ] control 2"
    }
    header "X-SKF-AUTH", "secret_skf_auth_token"
    post '/skf_comment', payload.to_json
    assert last_response.ok?
  end
end

