const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const axios = require('axios');

const AUTH0_DOMAIN = 'your-auth0-domain';
const AUTH0_AUDIENCE = 'your-auth0-audience';
const AUTH0_CLIENT_ID = 'your-auth0-client-id';
const AUTH0_CLIENT_SECRET = 'your-auth0-client-secret';

const client = jwksClient({
  jwksUri: `https://${AUTH0_DOMAIN}/.well-known/jwks.json`
});

exports.handler = async function(event, context) {
  // Extract the authorization token from the request headers
  const authorizationToken = event.headers.Authorization;

  // If no token is provided, deny access
  if (!authorizationToken) {
    return generatePolicy("user", "Deny", event.methodArn);
  }

  // Perform authentication and authorization checks based on the token
  const tokenParts = authorizationToken.split(' ');
  const tokenType = tokenParts[0];
  const tokenValue = tokenParts[1];

  if (tokenType !== 'Bearer') {
    return generatePolicy("user", "Deny", event.methodArn);
  }

  // Authenticate the token with Auth0
  let decodedToken;
  try {
    const kid = jwt.decode(tokenValue, { complete: true }).header.kid;
    const signingKey = await getSigningKey(kid);
    decodedToken = jwt.verify(tokenValue, signingKey);
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      // Token has expired, try refreshing it
      try {
        const refreshToken = 'your-refresh-token';
        const newAccessToken = await refreshAccessToken(refreshToken);
        decodedToken = jwt.verify(newAccessToken, signingKey);
      } catch (error) {
        return generatePolicy("user", "Deny", event.methodArn);
      }
    } else {
      return generatePolicy("user", "Deny", event.methodArn);
    }
  }

  // If the token is valid, allow access
  return generatePolicy(decodedToken.sub, "Allow", event.methodArn);
};

async function getSigningKey(kid) {
  const key = await new Promise((resolve, reject) => {
    client.getSigningKey(kid, (err, key) => {
      if (err) reject(err);
      resolve(key.publicKey || key.rsaPublicKey);
    });
  });
  return key;
}

async function refreshAccessToken(refreshToken) {
  const tokenEndpoint = `https://${AUTH0_DOMAIN}/oauth/token`;

  const response = await axios.post(tokenEndpoint, {
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    client_id: AUTH0_CLIENT_ID,
    client_secret: AUTH0_CLIENT_SECRET,
    audience: AUTH0_AUDIENCE
  });

  const newAccessToken = response.data.access_token;
  return newAccessToken;
}

function generatePolicy(principalId, effect, resource) {
  return {
    principalId: principalId,
    policyDocument: {
      Version: '2012-10-17',
      Statement: [
        {
          Action: 'execute-api:Invoke',
          Effect: effect,
          Resource: resource
        }
      ]
    }
  };
}
