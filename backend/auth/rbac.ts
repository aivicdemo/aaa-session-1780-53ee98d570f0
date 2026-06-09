export interface User {
  id: string;
  role: 'admin' | 'operator' | 'viewer';
}

export interface RBACPermissions {
  [endpoint: string]: {
    [method: string]: string[];
  };
}

export const permissions: RBACPermissions = {
  '/resources': {
    'GET': ['admin', 'operator', 'viewer']
  },
  '/api/users': {
    'GET': ['admin', 'operator', 'viewer'],
    'POST': ['admin'],
    'PUT': ['admin'],
    'DELETE': ['admin']
  },
  '/api/users/bulk': {
    'POST': ['admin', 'operator']
  },
  '/api/products': {
    'GET': ['admin', 'operator', 'viewer'],
    'POST': ['admin', 'operator'],
    'PUT': ['admin', 'operator'],
    'DELETE': ['admin']
  },
  '/api/products/bulk': {
    'POST': ['admin', 'operator']
  },
  '/api/product-specifications': {
    'GET': ['admin', 'operator', 'viewer'],
    'POST': ['admin', 'operator'],
    'PUT': ['admin', 'operator'],
    'DELETE': ['admin']
  },
  '/api/product-specifications/bulk': {
    'POST': ['admin', 'operator']
  },
  '/api/processes': {
    'GET': ['admin', 'operator', 'viewer'],
    'POST': ['admin', 'operator'],
    'PUT': ['admin', 'operator'],
    'DELETE': ['admin']
  },
  '/api/processes/bulk': {
    'POST': ['admin', 'operator']
  },
  '/api/materials': {
    'GET': ['admin', 'operator', 'viewer'],
    'POST': ['admin', 'operator'],
    'PUT': ['admin', 'operator'],
    'DELETE': ['admin']
  },
  '/api/materials/bulk': {
    'POST': ['admin', 'operator']
  },
  '/api/production-lines': {
    'GET': ['admin', 'operator', 'viewer'],
    'POST': ['admin', 'operator'],
    'PUT': ['admin', 'operator'],
    'DELETE': ['admin']
  },
  '/api/production-lines/bulk': {
    'POST': ['admin', 'operator']
  },
  '/api/production-orders': {
    'GET': ['admin', 'operator', 'viewer'],
    'POST': ['admin', 'operator'],
    'PUT': ['admin', 'operator'],
    'DELETE': ['admin']
  },
  '/api/production-orders/bulk': {
    'POST': ['admin', 'operator']
  },
  '/api/production-order-details': {
    'GET': ['admin', 'operator', 'viewer'],
    'POST': ['admin', 'operator'],
    'PUT': ['admin', 'operator'],
    'DELETE': ['admin']
  },
  '/api/production-order-details/bulk': {
    'POST': ['admin', 'operator']
  },
  '/api/work-results': {
    'GET': ['admin', 'operator', 'viewer'],
    'POST': ['admin', 'operator'],
    'PUT': ['admin', 'operator'],
    'DELETE': ['admin']
  },
  '/api/work-results/bulk': {
    'POST': ['admin', 'operator']
  },
  '/api/quality-inspections': {
    'GET': ['admin', 'operator', 'viewer'],
    'POST': ['admin', 'operator'],
    'PUT': ['admin', 'operator'],
    'DELETE': ['admin']
  },
  '/api/quality-inspections/bulk': {
    'POST': ['admin', 'operator']
  },
  '/api/process-handovers': {
    'GET': ['admin', 'operator', 'viewer'],
    'POST': ['admin', 'operator'],
    'PUT': ['admin', 'operator'],
    'DELETE': ['admin']
  },
  '/api/process-handovers/bulk': {
    'POST': ['admin', 'operator']
  },
  '/api/standard-procedures': {
    'GET': ['admin', 'operator', 'viewer'],
    'POST': ['admin', 'operator'],
    'PUT': ['admin', 'operator'],
    'DELETE': ['admin']
  },
  '/api/standard-procedures/bulk': {
    'POST': ['admin', 'operator']
  },
  '/api/quality-standards': {
    'GET': ['admin', 'operator', 'viewer'],
    'POST': ['admin', 'operator'],
    'PUT': ['admin', 'operator'],
    'DELETE': ['admin']
  },
  '/api/quality-standards/bulk': {
    'POST': ['admin', 'operator']
  },
  '/api/work-histories': {
    'GET': ['admin', 'operator', 'viewer'],
    'POST': ['admin', 'operator'],
    'PUT': ['admin', 'operator'],
    'DELETE': ['admin']
  },
  '/api/work-histories/bulk': {
    'POST': ['admin', 'operator']
  },
  '/api/progress-management': {
    'GET': ['admin', 'operator', 'viewer'],
    'POST': ['admin', 'operator'],
    'PUT': ['admin', 'operator'],
    'DELETE': ['admin']
  },
  '/api/progress-management/bulk': {
    'POST': ['admin', 'operator']
  },
  '/api/alert-notifications': {
    'GET': ['admin', 'operator', 'viewer'],
    'POST': ['admin', 'operator'],
    'PUT': ['admin', 'operator'],
    'DELETE': ['admin']
  },
  '/api/alert-notifications/bulk': {
    'POST': ['admin', 'operator']
  },
  '/api/anomaly-detection-logs': {
    'GET': ['admin', 'operator', 'viewer'],
    'POST': ['admin', 'operator'],
    'PUT': ['admin', 'operator'],
    'DELETE': ['admin']
  },
  '/api/anomaly-detection-logs/bulk': {
    'POST': ['admin', 'operator']
  }
};

export function hasPermission(user: User, endpoint: string, method: string): boolean {
  const endpointPermissions = permissions[endpoint];
  if (!endpointPermissions) {
    return false;
  }
  
  const methodPermissions = endpointPermissions[method];
  if (!methodPermissions) {
    return false;
  }
  
  return methodPermissions.includes(user.role);
}

export function extractUserFromEvent(event: any): User | null {
  try {
    const authHeader = event.headers?.Authorization || event.headers?.authorization;
    if (!authHeader) {
      return null;
    }
    
    const token = authHeader.replace('Bearer ', '');
    const decoded = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
    
    return {
      id: decoded.sub || decoded.userId,
      role: decoded.role || 'viewer'
    };
  } catch (error) {
    return null;
  }
}