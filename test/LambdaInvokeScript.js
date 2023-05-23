const AWS = require('aws-sdk');

AWS.config.update({ region: 'us-west-2' }); // Set the appropriate region

const lambda = new AWS.Lambda();

const invokeLambda = async () => {
  const functionName = 'your-lambda-function-name';
  const payload = {
    // Add any input payload data needed by your Lambda function
    key1: 'value1',
    key2: 'value2',
  };

  const params = {
    FunctionName: functionName,
    Payload: JSON.stringify(payload),
  };

  try {
    const response = await lambda.invoke(params).promise();
    const result = JSON.parse(response.Payload);

    // Handle the response from the Lambda function
    console.log('Invocation Result:', result);
  } catch (error) {
    // Handle any errors that occur during the invocation
    console.error('Error invoking Lambda:', error);
  }
};

invokeLambda();
