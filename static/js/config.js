
const API_CONFIG = {
  // Base URL for all API calls - UPDATE THIS FOR PRODUCTION
  // For local dev: 'http://localhost:5000'
  // For separate hosting: 'https://delta.gowshik.online'
  BASE_URL: 'https://delta.gowshik.online',
  

  
  // API Endpoints
  ENDPOINTS: {
    LOGIN: '/api/auth/login',
    SIGNUP: '/api/auth/signup',
    LOGOUT: '/api/auth/logout',
    CHECK_USERNAME: '/api/check-username',
    CHECK_EMAIL: '/api/check-email',
    VALIDATE_PASSWORD: '/api/validate-password',
    UPDATE: '/update',
    CHECK_AUTH: '/api/auth/check',
    USER_PROFILE: '/api/user/profile'
  },
  
  // Build full URL for an endpoint
  getUrl: function(endpoint) {
    return this.BASE_URL + endpoint;
  },
  
  // Default fetch options with credentials
  getFetchOptions: function(method = 'GET', body = null) {
    const options = {
      method: method,
      credentials: 'include', // Important for cookies/sessions across domains
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      }
    };
    
    if (body) {
      options.body = JSON.stringify(body);
    }
    
    return options;
  }
};

// Helper function for API calls
async function apiCall(endpoint, method = 'GET', body = null) {
  try {
    const url = API_CONFIG.getUrl(endpoint);
    const options = API_CONFIG.getFetchOptions(method, body);
    
    const response = await fetch(url, options);
    const data = await response.json();
    
    return {
      success: response.ok,
      status: response.status,
      data: data
    };
  } catch (error) {
    console.error('API Error:', error);
    return {
      success: false,
      status: 0,
      data: { error: 'Network error or server unavailable' }
    };
  }
}

// Export for use in other scripts
window.API_CONFIG = API_CONFIG;
window.apiCall = apiCall;
