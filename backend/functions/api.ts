import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, ScanCommand, GetCommand, PutCommand, UpdateCommand, DeleteCommand, BatchWriteCommand } from '@aws-sdk/lib-dynamodb';
import { hasPermission, extractUserFromEvent, User } from './rbac';
import { randomUUID } from 'crypto';

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

interface APIGatewayResponse {
  statusCode: number;
  headers?: { [key: string]: string };
  body: string;
}

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS'
};

function createResponse(statusCode: number, body: any): APIGatewayResponse {
  return {
    statusCode,
    headers: corsHeaders,
    body: JSON.stringify(body)
  };
}

async function createAuditLog(action: string, tableName: string, recordId: string, userId: string, details?: any) {
  const auditLog = {
    pk: 'AUDIT',
    sk: `${Date.now()}_${randomUUID()}`,
    action,
    tableName,
    recordId,
    userId,
    timestamp: new Date().toISOString(),
    details: details || {}
  };
  
  await docClient.send(new PutCommand({
    TableName: TABLE_NAME,
    Item: auditLog
  }));
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

function getTableConfig(path: string) {
  const configs = {
    '/api/users': { pk: 'USER', requiredFields: ['userName', 'passwordHash', 'fullName', 'permissionLevel', 'activeFlag', 'createdBy'] },
    '/api/products': { pk: 'PRODUCT', requiredFields: ['productCode', 'productName', 'productCategory', 'unit', 'activeFlag', 'createdBy', 'updatedBy'] },
    '/api/product-specifications': { pk: 'PRODUCT_SPEC', requiredFields: ['productId', 'specVersion', 'specName', 'effectiveStartDate', 'approvalStatus', 'createdBy'] },
    '/api/processes': { pk: 'PROCESS', requiredFields: ['processCode', 'processName', 'processCategory', 'usableFlag', 'createdBy', 'updatedBy'] },
    '/api/materials': { pk: 'MATERIAL', requiredFields: ['materialCode', 'materialName', 'materialCategory', 'unit', 'activeFlag', 'createdBy', 'updatedBy'] },
    '/api/production-lines': { pk: 'PRODUCTION_LINE', requiredFields: ['lineName', 'productId', 'processId', 'lineStatus', 'plannedQuantity', 'actualQuantity', 'defectQuantity', 'createdBy'] },
    '/api/production-orders': { pk: 'PRODUCTION_ORDER', requiredFields: ['orderNumber', 'productId', 'lineId', 'plannedQuantity', 'plannedStartDate', 'plannedEndDate', 'priority', 'status', 'createdBy'] },
    '/api/production-order-details': { pk: 'PRODUCTION_ORDER_DETAIL', requiredFields: ['orderId', 'detailNumber', 'productId', 'processId', 'lineId', 'plannedQuantity', 'unit', 'plannedStartDate', 'plannedEndDate', 'priority', 'status', 'createdBy', 'updatedBy'] },
    '/api/work-results': { pk: 'WORK_RESULT', requiredFields: ['orderId', 'orderDetailId', 'lineId', 'processId', 'startDate', 'actualQuantity', 'goodQuantity', 'defectQuantity', 'workerId', 'workStatus', 'createdBy'] },
    '/api/quality-inspections': { pk: 'QUALITY_INSPECTION', requiredFields: ['orderId', 'productId', 'processId', 'inspectionItem', 'judgmentResult', 'inspectionQuantity', 'inspectionDate', 'inspectorId', 'createdBy'] },
    '/api/process-handovers': { pk: 'PROCESS_HANDOVER', requiredFields: ['orderId', 'fromProcessId', 'toProcessId', 'lineId', 'lotNumber', 'handoverQuantity', 'workStatus', 'qualityStatus', 'handoverDate', 'handoverUserId', 'handoverStatus', 'createdBy'] },
    '/api/standard-procedures': { pk: 'STANDARD_PROCEDURE', requiredFields: ['procedureCode', 'procedureName', 'productId', 'processId', 'version', 'procedureContent', 'activeFlag', 'createdBy'] },
    '/api/quality-standards': { pk: 'QUALITY_STANDARD', requiredFields: ['standardName', 'inspectionItem', 'requiredInspectionFlag', 'effectiveStartDate', 'createdBy', 'updatedBy'] },
    '/api/work-histories': { pk: 'WORK_HISTORY', requiredFields: ['orderId', 'orderDetailId', 'processId', 'lineId', 'workerId', 'startDate', 'workStatus', 'createdBy'] },
    '/api/progress-management': { pk: 'PROGRESS_MANAGEMENT', requiredFields: ['orderId', 'orderDetailId', 'processId', 'lineId', 'plannedStartDate', 'plannedEndDate', 'plannedQuantity', 'completedQuantity', 'goodQuantity', 'defectQuantity', 'progressRate', 'processStatus', 'delayFlag', 'createdBy', 'updatedBy'] },
    '/api/alert-notifications': { pk: 'ALERT_NOTIFICATION', requiredFields: ['alertType', 'severity', 'title', 'messageContent', 'targetUserId', 'notificationStatus', 'readFlag', 'responseCompleteFlag', 'createdBy'] },
    '/api/anomaly-detection-logs': { pk: 'ANOMALY_LOG', requiredFields: ['lineId', 'processId', 'productId', 'orderId', 'detectionItem', 'detectedValue', 'anomalyLevel', 'detectionMethod', 'responseStatus', 'responsibleUserId', 'detectionDate', 'createdBy'] }
  };
  return configs[path];
}

async function handleBulkImport(path: string, body: any, user: User): Promise<APIGatewayResponse> {
  try {
    const { items } = body;
    if (!Array.isArray(items)) {
      return createResponse(400, { error: 'items must be an array' });
    }

    const config = getTableConfig(path.replace('/bulk', ''));
    if (!config) {
      return createResponse(404, { error: 'Table not found' });
    }

    let imported = 0;
    let failed = 0;
    const errors: string[] = [];
    const now = new Date().toISOString();

    // Process in batches of 25 (DynamoDB BatchWrite limit)
    for (let i = 0; i < items.length; i += 25) {
      const batch = items.slice(i, i + 25);
      const writeRequests = [];

      for (const item of batch) {
        try {
          const validationErrors = validateRequired(item, config.requiredFields);
          if (validationErrors.length > 0) {
            failed++;
            errors.push(`Item ${i + batch.indexOf(item)}: ${validationErrors.join(', ')}`);
            continue;
          }

          const enrichedItem = {
            ...item,
            pk: config.pk,
            sk: item.id || randomUUID(),
            id: item.id || randomUUID(),
            createdAt: now,
            updatedAt: now
          };

          writeRequests.push({
            PutRequest: {
              Item: enrichedItem
            }
          });
        } catch (error) {
          failed++;
          errors.push(`Item ${i + batch.indexOf(item)}: ${error}`);
        }
      }

      if (writeRequests.length > 0) {
        try {
          await docClient.send(new BatchWriteCommand({
            RequestItems: {
              [TABLE_NAME]: writeRequests
            }
          }));
          imported += writeRequests.length;
        } catch (error) {
          failed += writeRequests.length;
          errors.push(`Batch write failed: ${error}`);
        }
      }
    }

    await createAuditLog('BULK_IMPORT', config.pk, 'BULK', user.id, { imported, failed });

    return createResponse(200, { imported, failed, errors });
  } catch (error) {
    return createResponse(500, { error: 'Internal server error', details: error });
  }
}

export const handler = async (event: APIGatewayEvent): Promise<APIGatewayResponse> => {
  if (event.httpMethod === 'OPTIONS') {
    return createResponse(200, {});
  }

  try {
    const user = extractUserFromEvent(event);
    if (!user) {
      return createResponse(401, { error: 'Unauthorized' });
    }

    const path = event.path;
    const method = event.httpMethod;
    
    if (!hasPermission(user, path, method)) {
      return createResponse(403, { error: 'Forbidden' });
    }

    // Handle resources endpoint
    if (path === '/resources' && method === 'GET') {
      const resources = [
        { id: '1', name: 'ユーザー管理', endpoint: '/api/users' },
        { id: '2', name: '製品マスタ', endpoint: '/api/products' },
        { id: '3', name: '製品仕様', endpoint: '/api/product-specifications' },
        { id: '4', name: '工程マスタ', endpoint: '/api/processes' },
        { id: '5', name: '資材マスタ', endpoint: '/api/materials' },
        { id: '6', name: '製造ライン', endpoint: '/api/production-lines' },
        { id: '7', name: '生産指示書', endpoint: '/api/production-orders' },
        { id: '8', name: '生産指示書明細', endpoint: '/api/production-order-details' },
        { id: '9', name: '作業実績', endpoint: '/api/work-results' },
        { id: '10', name: '品質検査結果', endpoint: '/api/quality-inspections' },
        { id: '11', name: '工程引き継ぎ情報', endpoint: '/api/process-handovers' },
        { id: '12', name: '標準手順書', endpoint: '/api/standard-procedures' },
        { id: '13', name: '品質基準', endpoint: '/api/quality-standards' },
        { id: '14', name: '作業履歴', endpoint: '/api/work-histories' },
        { id: '15', name: '進捗管理', endpoint: '/api/progress-management' },
        { id: '16', name: 'アラート通知', endpoint: '/api/alert-notifications' },
        { id: '17', name: '異常値検出ログ', endpoint: '/api/anomaly-detection-logs' }
      ];
      return createResponse(200, { resources });
    }

    // Handle bulk import
    if (path.endsWith('/bulk') && method === 'POST') {
      const body = event.body ? JSON.parse(event.body) : {};
      return await handleBulkImport(path, body, user);
    }

    const config = getTableConfig(path);
    if (!config) {
      return createResponse(404, { error: 'Endpoint not found' });
    }

    const body = event.body ? JSON.parse(event.body) : {};
    const now = new Date().toISOString();

    switch (method) {
      case 'GET':
        if (event.pathParameters?.id) {
          // Get single item
          const result = await docClient.send(new GetCommand({
            TableName: TABLE_NAME,
            Key: {
              pk: config.pk,
              sk: event.pathParameters.id
            }
          }));
          
          if (!result.Item) {
            return createResponse(404, { error: 'Item not found' });
          }
          
          return createResponse(200, result.Item);
        } else {
          // Get all items
          const result = await docClient.send(new ScanCommand({
            TableName: TABLE_NAME,
            FilterExpression: 'pk = :pk',
            ExpressionAttributeValues: {
              ':pk': config.pk
            }
          }));
          
          return createResponse(200, { items: result.Items || [] });
        }

      case 'POST':
        const validationErrors = validateRequired(body, config.requiredFields);
        if (validationErrors.length > 0) {
          return createResponse(400, { error: 'Validation failed', details: validationErrors });
        }

        const newItem = {
          ...body,
          pk: config.pk,
          sk: body.id || randomUUID(),
          id: body.id || randomUUID(),
          createdAt: now,
          updatedAt: now
        };

        await docClient.send(new PutCommand({
          TableName: TABLE_NAME,
          Item: newItem
        }));

        await createAuditLog('CREATE', config.pk, newItem.id, user.id, newItem);
        return createResponse(201, newItem);

      case 'PUT':
        if (!event.pathParameters?.id) {
          return createResponse(400, { error: 'ID is required for update' });
        }

        const updateValidationErrors = validateRequired(body, config.requiredFields);
        if (updateValidationErrors.length > 0) {
          return createResponse(400, { error: 'Validation failed', details: updateValidationErrors });
        }

        const updatedItem = {
          ...body,
          pk: config.pk,
          sk: event.pathParameters.id,
          id: event.pathParameters.id,
          updatedAt: now
        };

        await docClient.send(new PutCommand({
          TableName: TABLE_NAME,
          Item: updatedItem
        }));

        await createAuditLog('UPDATE', config.pk, event.pathParameters.id, user.id, updatedItem);
        return createResponse(200, updatedItem);

      case 'DELETE':
        if (!event.pathParameters?.id) {
          return createResponse(400, { error: 'ID is required for delete' });
        }

        await docClient.send(new DeleteCommand({
          TableName: TABLE_NAME,
          Key: {
            pk: config.pk,
            sk: event.pathParameters.id
          }
        }));

        await createAuditLog('DELETE', config.pk, event.pathParameters.id, user.id);
        return createResponse(200, { message: 'Item deleted successfully' });

      default:
        return createResponse(405, { error: 'Method not allowed' });
    }
  } catch (error) {
    console.error('Error:', error);
    return createResponse(500, { error: 'Internal server error', details: error });
  }
};