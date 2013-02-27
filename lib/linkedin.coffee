url   = require 'url'

request = require 'request'
OAuth = require('oauth').OAuth

BASE = 'https://api.linkedin.com/v1'

module.exports = class LinkedIn
  constructor: (@key, @secret, @redirect, scopes) ->
    oauthBaseUrl = 'https://api.linkedin.com/uas/oauth'
    requestTokenUrl = oauthBaseUrl + '/requestToken'
    if scopes
      requestTokenUrl += "?scope=#{scopes.join '+'}"
    accessTokenUrl = oauthBaseUrl + '/accessToken'
    @oauth = new OAuth(
      requestTokenUrl
      accessTokenUrl
      @key
      @secret
      '1.0'
      @redirect
      'HMAC-SHA1'
      null
      'Accept': '*/*', 'Connection': 'close'
    )

  #
  # Does an API call to linkedin and callbacks
  # when the result is available.
  #
  # @param {String} method
  # @param {String} path
  # @param {Object} params
  # @param {Function} callback
  # @return {Request}
  #
  apiCall: (method, path, params, callback) =>
    token = params.token
    delete params.token
    oauth =
      consumer_key: @key
      consumer_secret: @secret
      token: token.oauth_token
      token_secret: token.oauth_token_secret
    params =
      method: method
      url: BASE + path
      json: true
      oauth: oauth
      headers: 'x-li-format': 'json'
    request params, (err, resp, body) =>
      return callback err, null if err
      callback null, body

  #
  # Redirects to linkedin to retrieve the token
  # or callbacks with the proper token
  #
  # @param {Request} req
  # @param {Response} res
  # @param {Function} callback
  #
  getAccessToken:  (req, res, callback) =>
    parsedUrl = url.parse req.url, true
    hasToken  = parsedUrl?.query?.oauth_token?
    hasSecret = req.session?.auth?.linkedin_oauth_token_secret?

    # Access token
    if hasToken and hasSecret
      @oauth.getOAuthAccessToken(
        parsedUrl.query.oauth_token
        req.session.auth.linkedin_oauth_token_secret
        parsedUrl.query.oauth_verifier
        (err, oauth_token, oauth_token_secret, additionalParams) =>
          return callback err, null if err
          callback null, {oauth_token, oauth_token_secret}
      )

    # Request token
    else
      @oauth.getOAuthRequestToken(
        oauth_callback: @redirect
        (err, oauth_token, oauth_token_secret, oauth_authorize_url, additionalParams) =>
          return callback err, null if err
          req.session.linkedin_redirect_url = req.url
          req.session.auth = req.session.auth or {}
          req.session.auth.linkedin_oauth_token_secret = oauth_token_secret
          req.session.auth.linkedin_oauth_token = oauth_token
          res.redirect "https://www.linkedin.com/uas/oauth/authenticate?oauth_token=#{oauth_token}"
      )
