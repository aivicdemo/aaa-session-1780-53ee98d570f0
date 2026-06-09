import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, ScanCommand, GetCommand, PutCommand, UpdateCommand, DeleteCommand, BatchWriteCommand } from '@aws-sdk/lib-dynamodb';
import { extractRoleFromEvent, hasPermission, Role } from './rbac';
import * as crypto from 'crypto';

const client = new DynamoDBClient({});
const docClient = DynamoDBDocumentClient.from(client);
const TABLE_NAME = process.env.MAIN_TABLE!;

interface APIGatewayEvent {
  httpMethod: string;
  path: string;
  pathParameters?: { [key: string]: string };
  queryStringParameters?: { [key: string]: string };
  body?: string;
  headers?: { [key: string]: string };
}

interface APIResponse {
  statusCode: number;
  headers: { [key: string]: string };
  body: string;
}

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization'
};

const TABLE_CONFIGS = {
  'users': { pk: 'USER', name: 'ユーザー' },
  'products': { pk: 'PRODUCT', name: '製品マスタ' },
  'product-specs': { pk: 'PRODUCT_SPEC', name: '製品仕様' },
  'processes': { pk: 'PROCESS', name: '工程マスタ' },
  'production-lines': { pk: 'PRODUCTION_LINE', name: '製造ライン' },
  'materials': { pk: 'MATERIAL', name: '資材マスタ' },
  'production-plans': { pk: 'PRODUCTION_PLAN', name: '生産計画' },
  'work-orders': { pk: 'WORK_ORDER', name: '生産指示書' },
  'work-results': { pk: 'WORK_RESULT', name: '作業実績' },
  'quality-inspections': { pk: 'QUALITY_INSPECTION', name: '品質検査結果' },
  'progress-management': { pk: 'PROGRESS', name: '進捗管理' },
  'alert-notifications': { pk: 'ALERT', name: 'アラート通知' },
  'work-history': { pk: 'WORK_HISTORY', name: '作業履歴' },
  'standard-procedures': { pk: 'STANDARD_PROCEDURE', name: '標準手順書' },
  'quality-standards': { pk: 'QUALITY_STANDARD', name: '品質基準' },
  'anomaly-logs': { pk: 'ANOMALY_LOG', name: '異常値検出ログ' }
};

function createResponse(statusCode: number, body: any): APIResponse {
  return {
    statusCode,
    headers: CORS_HEADERS,
    body: JSON.stringify(body)
  };
}

function validateRequired(data: any, requiredFields: string[]): string[] {
  const errors: string[] = [];
  for (const field of requiredFields) {
    if (!data[field]) {
      errors.push(`${field} is required`);
    }
  }
  return errors;
}

async function createAuditLog(action: string, tableName: string, itemId: string, userId: string, details?: any): Promise<void> {
  const auditItem = {
    pk: 'AUDIT',
    sk: `${Date.now()}_${crypto.randomUUID()}`,
    action,
    tableName,
    itemId,
    userId,
    details,
    timestamp: new Date().toISOString()
  };
  
  await docClient.send(new PutCommand({
    TableName: TABLE_NAME,
    Item: auditItem
  }));
}

function getTableConfig(path: string): { tableName: string; config: any } | null {
  const match = path.match(/^\/resources$/);
  if (match) {
    return { tableName: 'resources', config: { pk: 'RESOURCE', name: 'リソース' } };
  }
  
  const bulkMatch = path.match(/^\/api\/(\w+(?:-\w+)*)/bulk$/);
  if (bulkMatch) {
    const tableName = bulkMatch[1];
    const config = TABLE_CONFIGS[tableName as keyof typeof TABLE_CONFIGS];
    if (config) {
      return { tableName, config };
    }
  }
  
  return null;
}

export async function handler(event: APIGatewayEvent): Promise<APIResponse> {
  try {
    if (event.httpMethod === 'OPTIONS') {
      return createResponse(200, {});
    }

    const role = extractRoleFromEvent(event);
    const path = event.path;
    const method = event.httpMethod;
    
    // GET /resources エンドポイント
    if (method === 'GET' && path === '/resources') {
      if (!hasPermission(role, 'read')) {
        return createResponse(403, { error: 'Insufficient permissions' });
      }

      try {
        const command = new ScanCommand({
          TableName: TABLE_NAME,
          FilterExpression: 'pk = :pk',
          ExpressionAttributeValues: {
            ':pk': 'RESOURCE'
          }
        });
        
        const result = await docClient.send(command);
        return createResponse(200, {
          items: result.Items || [],
          count: result.Count || 0
        });
      } catch (error) {
        console.error('Error fetching resources:', error);
        return createResponse(500, { error: 'Internal server error' });
      }
    }

    // 一括インポートエンドポイント
    const bulkMatch = path.match(/^\/api\/(\w+(?:-\w+)*)/bulk$/);
    if (method === 'POST' && bulkMatch) {
      const tableName = bulkMatch[1];
      const config = TABLE_CONFIGS[tableName as keyof typeof TABLE_CONFIGS];
      
      if (!config) {
        return createResponse(404, { error: 'Table not found' });
      }

      if (!hasPermission(role, 'bulk')) {
        return createResponse(403, { error: 'Insufficient permissions for bulk operations' });
      }

      if (!event.body) {
        return createResponse(400, { error: 'Request body is required' });
      }

      try {
        const { items } = JSON.parse(event.body);
        
        if (!Array.isArray(items)) {
          return createResponse(400, { error: 'items must be an array' });
        }

        let imported = 0;
        let failed = 0;
        const errors: string[] = [];
        const now = new Date().toISOString();

        // 25件ずつに分割してバッチ処理
        for (let i = 0; i < items.length; i += 25) {
          const batch = items.slice(i, i + 25);
          const writeRequests = batch.map(item => {
            const enrichedItem = {
              ...item,
              pk: config.pk,
              sk: item.id || crypto.randomUUID(),
              id: item.id || crypto.randomUUID(),
              createdAt: now,
              updatedAt: now
            };

            return {
              PutRequest: {
                Item: enrichedItem
              }
            };
          });

          try {
            await docClient.send(new BatchWriteCommand({
              RequestItems: {
                [TABLE_NAME]: writeRequests
              }
            }));
            imported += batch.length;
          } catch (error) {
            failed += batch.length;
            errors.push(`Batch ${Math.floor(i/25) + 1}: ${error}`);
          }
        }

        // 監査ログ記録
        await createAuditLog(
          'BULK_IMPORT',
          tableName,
          'BULK',
          'system',
          { imported, failed, total: items.length }
        );

        return createResponse(200, {
          imported,
          failed,
          errors
        });
      } catch (error) {
        console.error('Bulk import error:', error);
        return createResponse(500, { error: 'Internal server error' });
      }
    }

    return createResponse(404, { error: 'Endpoint not found' });
    
  } catch (error) {
    console.error('Handler error:', error);
    return createResponse(500, { error: 'Internal server error' });
  }
}