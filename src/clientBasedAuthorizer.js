const jwt = require('jsonwebtoken');
const axios = require('axios');

exports.handler = async (event, context) => {
  const token = event.authorizationToken.split(' ')[1];
  const jwksUri = 'https://your-auth0-domain.auth0.com/.well-known/jwks.json';
  const audience = 'your-auth0-audience';
  const issuer = 'https://your-auth0-domain.auth0.com/';
  const clientId = 'your-auth0-client-id';
  const clientSecret = 'your-auth0-client-secret';

  try {
    // Get access token to authenticate with the JWKS endpoint
    const authResponse = await axios.post('https://your-auth0-domain.auth0.com/oauth/token', {
      client_id: clientId,
      client_secret: clientSecret,
      audience: jwksUri,
      grant_type: 'client_credentials'
    });

    const accessToken = authResponse.data.access_token;

    // Retrieve JWKS with the access token
    const jwksResponse = await axios.get(jwksUri, {
      headers: {
        Authorization: `Bearer ${accessToken}`
      }
    });

    const jwks = jwksResponse.data;

    const signingKey = jwks.keys[0]; // Assuming only one key in the JWKS, modify as needed

    const decoded = jwt.verify(token, signingKey, {
      audience,
      issuer
    });

    // Your authorization logic goes here

    return generatePolicy(decoded.sub, 'Allow', event.methodArn);
  } catch (error) {
    console.error(error);
    return generatePolicy('user', 'Deny', event.methodArn);
  }
};
