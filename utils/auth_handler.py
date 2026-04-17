from getpass import getpass
import json
import time

import utils.log_handler as logger
log = logger.log
import api
import utils.input_utils as input

class Auth():
    
    def __init__(self, args):
        self.base_url = args.get('instance_url')
        self.cf_token = args.get('cf_token')
        self.username = args.get('username')
        self.password = args.get('password')
        self.tenant_id = None
        self.auth_headers = {}

        self.time_since_last_auth = None


    def add_auth_header(self, authorization_token):
        self.auth_headers["Authorization"] = authorization_token


    def add_cf_auth_header(self, cf_token):
        self.auth_headers["cf-access-token"] = cf_token


    def get_auth_headers(self):
        """
        checks is authorization is current and returns headers, otherwise tries to re-authenticate and return new auth headers

        to prevent the auth from timing out after it was checked, but before it can be received by the API,
        checks whether we are in the last minute of the 15 min auth window
        """
        if self.time_since_last_auth == None:
            self.handle_authentication()

        if time.time() - self.time_since_last_auth > 840:
            self.handle_authentication()
        
        return self.auth_headers


    def handle_instance_url(self):
        """
        prompts user for their plextrac url, checks that the API is up and running, then sets the url
        """
        if self.base_url == None:
            self.base_url = input.prompt_user("Please enter the full URL of your PlexTrac instance (with protocol)")
        else:
            log.info(f'Using instance_url from config...')

        #validate
        try:
            response = api.tenant.root_request(self.base_url, {}) # non authenticated endpoint - does not require any headers - used to see if we can connect to the api
            log.debug(response)
            if not response.has_json_response: # if the base_url is not valid, the response will not contain any JSON
                if input.retry("Could not validate URL. Either the API is offline or it was entered incorrectly\nExample: https://company.plextrac.com"):
                    self.cf_token = None
                    self.base_url = None
                    return self.handle_instance_url()

            try:
                if response.json.get('text') == "Authenticate at /authenticate":
                    log.success("Validated instance URL")
                    
            except Exception as e: # potential plextrac internal instance running behind Cloudflare
                if self.cf_token == None:
                    option = input.user_options("That URL points to a running verson of Plextrac. However, the API did not respond.\nThere might be an additional layer of security. Try adding Cloudflare auth token?", "Do you want to try adding a Cloudflare token?", ['y', 'n'])    
                    if option == 'y':
                        return self.handle_cf_instance_url()
                else:
                    return self.handle_cf_instance_url()
            
                if input.retry("Could not validate instance URL."):
                    self.cf_token = None
                    return self.handle_instance_url()

        except Exception as e:
            log.exception(e)
            if input.retry("Could not validate URL. Either the API is offline or it was entered incorrectly\nExample: https://company.plextrac.com"):
                self.base_url = None
                return self.handle_instance_url()


    def handle_cf_instance_url(self):
        """
        handles extra layer of Cloudflare authorization
        plextrac test instances are hosted behind a Cloudflare wall that requires another layer of authorization
        """
        if self.cf_token == None:
            self.cf_token = input.prompt_user("Please enter your active 'CF_Authorization' token")
        else:
            log.info(f'Using cf_token from config...')

        response = api.tenant.root_request(self.base_url, headers={"cf-access-token": self.cf_token})
            
        if response.json.get('text') != "Authenticate at /authenticate":
            if input.retry("Could not validate instance URL."):
                self.cf_token = None
                return self.handle_instance_url()

        self.add_cf_auth_header(self.cf_token)
        log.success("Validated instance URL")


    def handle_authentication(self):
        log.info('---Starting Authorization---')

        self.handle_instance_url()
        log.info(f'Available login method:\n1. Username & Password\n2. Auth Token')
        method = input.prompt_user("Please choose which method to use for login(1 or 2)")
        if method == "1":
            if self.username == None:
                self.username = input.prompt_user("Please enter your PlexTrac username")
            else:
                log.info(f'Using username from config...')
            if self.password == None:
                self.password = getpass(prompt="Password: ")
            else:
                log.info(f'Using password from config...')
            
            authenticate_data = {
                "username": self.username,
                "password": self.password
            }
            response = api._authentication.authenticate.authentication(self.base_url, self.auth_headers, authenticate_data)
            # the following conditional can fail due to:
            # - invalid credentials
            # - if the instance is setup to requre mfa and use user does not have mfa setup
            # - other
            # the api response is purposely non-descript to prevent gaining information about the authentication process
            if response.json.get('status') != "success":
                if input.retry("Could not authenticate with entered credentials."):
                    self.username = None
                    self.password = None
                    self.tenant_id = None
                    return self.handle_authentication()
            
            self.tenant_id = response.json.get('tenant_id')

            if response.json.get('mfa_enabled'):
                log.info('MFA detected for user')

                mfa_auth_data = {
                    "code": response.json.get('code'),
                    "token": input.prompt_user("Please enter your 6 digit MFA code")
                }
                
                response = api._authentication.authenticate.multi_factor_authentication(self.base_url, self.auth_headers, mfa_auth_data)
                if response.json.get('status') != "success":
                    if input.retry("Invalid MFA Code."):
                        return self.handle_authentication()
            
            self.add_auth_header(response.json.get('token'))
        elif method == "2":
            auth = input.prompt_user("Insert token")
            self.add_auth_header(auth)
        else:
            log.info(f'Please only choose 1 or 2 for the login method.')

        self.time_since_last_auth = time.time()
        log.success('Authenticated')
