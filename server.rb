require 'sinatra'
require 'octokit'
require 'dotenv/load' # Manages environment variables
require 'json'
require 'openssl'     # Verifies the webhook signature
require 'jwt'         # Authenticates a GitHub App
require 'time'        # Gets ISO 8601 representation of a Time object
require 'logger'      # Logs debug statements
require 'httparty'
require 'pry'

set :port, 3000
set :bind, '0.0.0.0'



class GHAapp < Sinatra::Application

  # Converts the newlines. Expects that the private key has been set as an
  # environment variable in PEM format.
  GITHUB_PRIVATE_KEY = OpenSSL::PKey::RSA.new(ENV['GITHUB_PRIVATE_KEY'].gsub('\n', "\n"))
  SKF_PRIVATE_KEY = OpenSSL::PKey::RSA.new(ENV['SKF_PRIVATE_KEY'].gsub('\n', "\n"))

  INSTALLATION_ID = ENV['INSTALLATION_ID']

  SKF_ENDPOINT = ENV['SKF_ENDPOINT']

  # Your registered app must have a secret set. The secret is used to verify
  # that webhooks are sent by GitHub.
  WEBHOOK_SECRET = ENV['GITHUB_WEBHOOK_SECRET']

  # The GitHub App's identifier (type integer) set when registering an app.
  APP_IDENTIFIER = ENV['GITHUB_APP_IDENTIFIER']

  # Turn on Sinatra's verbose logging during development
  configure :development do
    set :logging, Logger::DEBUG
  end


  # Executed before each request to the `/event_handler` route
  before '/' do
    authenticate_app
    # Authenticate the app installation in order to run API operations
    authenticate_installation
  end


  post '/' do
    get_payload_request(request)
    verify_webhook_signature
    case request.env['HTTP_X_GITHUB_EVENT']
    when 'issues'
      if @payload['action'] == 'labeled' && @payload['label']['name'] == 'SKF'
        add_link_to_github_issue(@payload)
      end
    end
    200 # success status
  end


  helpers do

    def add_link_to_github_issue(payload)
      repo = @payload['repository']['full_name']
      issue_number = @payload['issue']['number']
      message = "Click here to set up your SKF security controls: #{skf_link(repo, issue_number)}"
      @installation_client.add_comment(repo, issue_number, message)
    end

    def skf_link(repo, issue_number)
      payload = {
        repo: repo,
        issue_number: issue_number
      }

      # Cryptographically sign the JWT.
      jwt = JWT.encode(payload, SKF_PRIVATE_KEY, 'RS256')
      "#{SKF_ENDPOINT}?token=#{jwt}"
    end
    
    def add_requirements_to_github_issue(payload)
      repo = @payload['repository']['full_name']
      issue_number = @payload['issue']['number']
      #first iterate over the labels and see if there is anything we want to use 
      labels = @installation_client.labels_for_issue(repo, issue_number)
      #We take al the checklists from SKF and iterate over it to ultimately give back the right list
      response_raw = HTTParty.get('https://beta.securityknowledgeframework.org/api/checklist/types', :verify => false)
      #Loop for each label comming from github
      labels.each do |label|
        #Also loop all the available checklists from SKF
        response_raw['items'].each do |checklist|
          #When we have a match
          if label['name'] == checklist['title']
            #All the requirements and knowledgebase items are fetched from the SKF API
            checklist_response = HTTParty.get("https://beta.securityknowledgeframework.org/api/checklist/item/gitplugin/#{checklist["checklist_type"]}", :verify => false)
            logger.debug checklist_response
            #before we want to add the content to the issue we make pretty markdown of it
            markdown = make_nice_markdown(checklist_response)
            #And appended to the github issue as a bot comment
            my_str = "foobar"
            @installation_client.add_comment(repo, issue_number, markdown)
          end
        end
      end
    end

    def make_nice_markdown(markme)
       message = ""
       message << '![alt text](https://raw.githubusercontent.com/blabla1337/skf-www/master/img/logos/logo-purple.png "Security knowledge framework")'
       message << "\n"
       message << "## Security knowledge framework!"
       message << "\n"
       markme['items'].each do |mark|
          message << "\n"
          message << "\n"
          message << "___"
          message << "\n"
          message << "\n"
          message << "- [ ] #{mark['checklist_items_checklistID']} #{mark['checklist_items_content']}"
          message << "\n"
          message << "<details>"
          message << "<summary>"
          message << "More information"
          message << "</summary>"
          message << "\n"
          message << "\n"
          message << "```"
          message << "\n"
          message << "#{mark['kb_item_title']}"
          message << "\n"
          message << "\n"
          message << "#{mark['kb_items_content']}"
          message << "\n"
          message << "```"
          message << "\n"
          message << "</details>"
        end
      message
    end
    
    # Saves the raw payload and converts the payload to JSON format
    def get_payload_request(request)
      # request.body is an IO or StringIO object
      # Rewind in case someone already read it
      request.body.rewind
      # The raw text of the body is required for webhook signature verification
      @payload_raw = request.body.read
      begin
        @payload = JSON.parse @payload_raw
      rescue => e
        fail  "Invalid JSON (#{e}): #{@payload_raw}"
      end
    end

    # Instantiate an Octokit client authenticated as a GitHub App.
    # GitHub App authentication requires that you construct a
    # JWT (https://jwt.io/introduction/) signed with the app's private key,
    # so GitHub can be sure that it came from the app an not altererd by
    # a malicious third party.
    def authenticate_app
      payload = {
          # The time that this JWT was issued, _i.e._ now.
          iat: Time.now.to_i,

          # JWT expiration time (10 minute maximum)
          exp: Time.now.to_i + (10 * 60),

          # Your GitHub App's identifier number
          iss: APP_IDENTIFIER
      }

      # Cryptographically sign the JWT.
      jwt = JWT.encode(payload, GITHUB_PRIVATE_KEY, 'RS256')

      # Create the Octokit client, using the JWT as the auth token.
      @app_client ||= Octokit::Client.new(bearer_token: jwt)
    end

    # Instantiate an Octokit client, authenticated as an installation of a
    # GitHub App, to run API operations.
    def authenticate_installation(payload)
      @installation_token = @app_client.create_app_installation_access_token(INSTALLATION_ID)[:token]
      @installation_client = Octokit::Client.new(bearer_token: @installation_token)
    end

    # Check X-Hub-Signature to confirm that this webhook was generated by
    # GitHub, and not a malicious third party.
    #
    # GitHub uses the WEBHOOK_SECRET, registered to the GitHub App, to
    # create the hash signature sent in the `X-HUB-Signature` header of each
    # webhook. This code computes the expected hash signature and compares it to
    # the signature sent in the `X-HUB-Signature` header. If they don't match,
    # this request is an attack, and you should reject it. GitHub uses the HMAC
    # hexdigest to compute the signature. The `X-HUB-Signature` looks something
    # like this: "sha1=123456".
    # See https://developer.github.com/webhooks/securing/ for details.
    def verify_webhook_signature
      their_signature_header = request.env['HTTP_X_HUB_SIGNATURE'] || 'sha1='
      method, their_digest = their_signature_header.split('=')
      our_digest = OpenSSL::HMAC.hexdigest(method, WEBHOOK_SECRET, @payload_raw)
      halt 401 unless their_digest == our_digest

      # The X-GITHUB-EVENT header provides the name of the event.
      # The action value indicates the which action triggered the event.
      logger.debug "---- received event #{request.env['HTTP_X_GITHUB_EVENT']}"
      logger.debug "----    action #{@payload['action']}" unless @payload['action'].nil?
    end

  end

  # Finally some logic to let us run this server directly from the command line,
  # or with Rack. Don't worry too much about this code. But, for the curious:
  # $0 is the executed file
  # __FILE__ is the current file
  # If they are the same—that is, we are running this file directly, call the
  # Sinatra run method
  run! if __FILE__ == $0
end
