// backend/utils.js

export const authenticateJWT = (req, res, next) => {
  // Dummy middleware for testing
  next();
};

export const logAction = (action, data) => {
  console.log(`Action: ${action}`, data);
};

export const io = {
  emit: (event, data) => {
    console.log(`Emit event: ${event}`, data);
  },
};

export const sendEmail = async ({ to, subject, html }) => {
  console.log(`Send email to ${to} with subject ${subject}`);
};

export const recoveryHistory = [];
