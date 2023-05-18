const axios = require('axios');
const jwt = require('jsonwebtoken');

const { handler } = require('./authorizer');

const AUTH0_DOMAIN = 'your-auth0-domain';
const CLIENT_ID = 'your-client-id';
const CLIENT_SECRET = 'your-client-secret';

const generateValidToken = async () => {
  const auth0TokenEndpoint = `https://${AUTH0_DOMAIN}/oauth/token`;

  const response = await axios.post(auth0TokenEndpoint, {
    grant_type: 'client_credentials',
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    audience: 'your-auth0-api-audience',
  });

  const accessToken = response.data.access_token;

  const payload = {
    // Add the necessary claims to the token payload
    sub: 'user123',
    // ...
  };

  const options = {
    expiresIn: '1h', // Set an appropriate expiration time
    audience: 'your-audience', // Replace with the expected audience
    issuer: `https://${AUTH0_DOMAIN}/`, // Replace with the expected issuer
  };

  const token = jwt.sign(payload, accessToken, options);
  return token;
};

// Usage in the test case
const event = {
  headers: {
    Authorization: `Bearer ${generateValidToken()}`,
  },
  methodArn: 'arn:aws:execute-api:us-west-2:123456789012:my-api/my-stage/GET/resource',
};


describe('Lambda Authorizer', () => {
  it('should allow access with a valid token', async () => {
    // const event = {
    //   headers: {
    //     Authorization: 'Bearer valid-access-token'
    //   },
    //   methodArn: 'arn:aws:execute-api:us-west-2:123456789012:my-api/my-stage/GET/resource'
    // };

    const context = {};

    const result = await handler(event, context);
    expect(result).toEqual({
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: 'arn:aws:execute-api:us-west-2:123456789012:my-api/my-stage/GET/resource'
          }
        ]
      }
    });
  });

  it('should deny access with an invalid token', async () => {
    const event = {
      headers: {
        Authorization: 'Bearer invalid-access-token'
      },
      methodArn: 'arn:aws:execute-api:us-west-2:123456789012:my-api/my-stage/GET/resource'
    };

    const context = {};

    const result = await handler(event, context);
    expect(result).toEqual({
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: 'arn:aws:execute-api:us-west-2:123456789012:my-api/my-stage/GET/resource'
          }
        ]
      }
    });
  });

});
