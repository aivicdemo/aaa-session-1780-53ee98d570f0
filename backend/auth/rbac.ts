export type Role = 'admin' | 'operator' | 'viewer';

export interface Permission {
  create: boolean;
  read: boolean;
  update: boolean;
  delete: boolean;
  bulk: boolean;
}

export const ROLE_PERMISSIONS: Record<Role, Permission> = {
  admin: {
    create: true,
    read: true,
    update: true,
    delete: true,
    bulk: true
  },
  operator: {
    create: true,
    read: true,
    update: true,
    delete: false,
    bulk: true
  },
  viewer: {
    create: false,
    read: true,
    update: false,
    delete: false,
    bulk: false
  }
};

export function hasPermission(role: Role, action: keyof Permission): boolean {
  return ROLE_PERMISSIONS[role][action];
}

export function extractRoleFromEvent(event: any): Role {
  const authHeader = event.headers?.Authorization || event.headers?.authorization;
  if (!authHeader) return 'viewer';
  
  try {
    const token = authHeader.replace('Bearer ', '');
    const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
    return payload.role || 'viewer';
  } catch {
    return 'viewer';
  }
}