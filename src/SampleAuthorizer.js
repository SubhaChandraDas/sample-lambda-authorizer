const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const AUTH0_DOMAIN = 'your-auth0-domain';
const AUTH0_AUDIENCE = 'your-auth0-audience';

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
    decodedToken = jwt.verify(tokenValue, signingKey, {
      issuer: `https://${AUTH0_DOMAIN}/`,
      audience: AUTH0_AUDIENCE
    });
  } catch (err) {
    return generatePolicy("user", "Deny", event.methodArn);
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

