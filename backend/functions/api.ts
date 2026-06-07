import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, ScanCommand, GetCommand, PutCommand, UpdateCommand, DeleteCommand, BatchWriteCommand } from '@aws-sdk/lib-dynamodb';
import { extractUserFromEvent, hasPermission } from './rbac';
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
  headers: { [key: string]: string };
}

interface APIGatewayResponse {
  statusCode: number;
  headers: { [key: string]: string };
  body: string;
}

const tableConfigs = {
  '0': { name: 'users', pk: 'USER' },
  '1': { name: 'products', pk: 'PRODUCT' },
  '2': { name: 'product_specs', pk: 'PRODUCT_SPEC' },
  '3': { name: 'processes', pk: 'PROCESS' },
  '4': { name: 'materials', pk: 'MATERIAL' },
  '5': { name: 'production_lines', pk: 'PRODUCTION_LINE' },
  '6': { name: 'production_orders', pk: 'PRODUCTION_ORDER' },
  '7': { name: 'production_order_details', pk: 'PRODUCTION_ORDER_DETAIL' },
  '8': { name: 'work_results', pk: 'WORK_RESULT' },
  '9': { name: 'quality_inspections', pk: 'QUALITY_INSPECTION' },
  '10': { name: 'process_handovers', pk: 'PROCESS_HANDOVER' },
  '11': { name: 'standard_procedures', pk: 'STANDARD_PROCEDURE' },
  '12': { name: 'quality_standards', pk: 'QUALITY_STANDARD' },
  '13': { name: 'work_history', pk: 'WORK_HISTORY' },
  '14': { name: 'progress_management', pk: 'PROGRESS_MANAGEMENT' },
  '15': { name: 'alert_notifications', pk: 'ALERT_NOTIFICATION' },
  '16': { name: 'anomaly_detection_logs', pk: 'ANOMALY_DETECTION_LOG' }
};

function createResponse(statusCode: number, body: any): APIGatewayResponse {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    },
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

async function writeAuditLog(action: string, resource: string, userId: string, details?: any): Promise<void> {
  try {
    await docClient.send(new PutCommand({
      TableName: TABLE_NAME,
      Item: {
        pk: 'AUDIT',
        sk: `${Date.now()}_${randomUUID()}`,
        action,
        resource,
        userId,
        details,
        timestamp: new Date().toISOString()
      }
    }));
  } catch (error) {
    console.error('Failed to write audit log:', error);
  }
}

function getTableConfig(tableIndex: string) {
  const config = tableConfigs[tableIndex as keyof typeof tableConfigs];
  if (!config) {
    throw new Error(`Invalid table index: ${tableIndex}`);
  }
  return config;
}

function getRequiredFields(tableIndex: string): string[] {
  const requiredFieldsMap: { [key: string]: string[] } = {
    '0': ['userName', 'passwordHash', 'fullName', 'authorityLevel', 'activeFlag'],
    '1': ['productCode', 'productName', 'unit', 'activeFlag'],
    '2': ['productId', 'specVersion', 'specName', 'effectiveStartDate', 'approvalStatus'],
    '3': ['processCode', 'processName', 'activeFlag'],
    '4': ['materialCode', 'materialName', 'materialCategory', 'unit', 'activeFlag'],
    '5': ['lineCode', 'lineName', 'factoryCode', 'lineType', 'operationStatus', 'activeFlag'],
    '6': ['productionOrderNumber', 'productId', 'productionLineId', 'plannedQuantity', 'plannedStartDateTime', 'plannedEndDateTime', 'priority', 'status'],
    '7': ['productionOrderId', 'detailNumber', 'productId', 'processId', 'productionLineId', 'orderQuantity', 'unit', 'plannedStartDateTime', 'plannedEndDateTime', 'progressStatus', 'priority'],
    '8': ['productionOrderDetailId', 'processId', 'productionLineId', 'workerId', 'workStartDateTime', 'plannedQuantity', 'workStatus'],
    '9': ['productionOrderId', 'productId', 'processId', 'inspectionItemName', 'judgmentResult', 'inspectionQuantity', 'inspectionDateTime', 'inspectorId'],
    '10': ['productionOrderId', 'sourceProcessId', 'targetProcessId', 'productId', 'lotNumber', 'handoverQuantity', 'workStatus', 'qualityStatus', 'handoverDateTime', 'handoverUserId', 'handoverStatus'],
    '11': ['procedureCode', 'procedureName', 'productId', 'processId', 'version', 'procedureContent', 'activeFlag', 'approvalStatus'],
    '12': ['standardName', 'inspectionItemName', 'requiredFlag', 'effectiveStartDate'],
    '13': ['productionOrderId', 'processId', 'productionLineId', 'workerId', 'workStartDateTime', 'workContent', 'workStatus'],
    '14': ['productionOrderId', 'processId', 'productionLineId', 'plannedStartDateTime', 'plannedEndDateTime', 'plannedQuantity', 'completedQuantity', 'progressRate', 'progressStatus', 'delayFlag'],
    '15': ['alertType', 'importance', 'title', 'messageContent', 'targetUserId', 'notificationStatus', 'activeFlag'],
    '16': ['productionLineId', 'processId', 'detectionItemName', 'detectedValue', 'anomalyLevel', 'detectionMethod', 'responseStatus', 'detectionDateTime']
  };
  return requiredFieldsMap[tableIndex] || [];
}

export const handler = async (event: APIGatewayEvent): Promise<APIGatewayResponse> => {
  try {
    if (event.httpMethod === 'OPTIONS') {
      return createResponse(200, {});
    }

    const user = extractUserFromEvent(event);
    const pathParts = event.path.split('/').filter(p => p);
    
    if (pathParts[0] === 'resources') {
      if (event.httpMethod === 'GET') {
        if (!hasPermission(user, 'resources', 'read')) {
          return createResponse(403, { error: 'Insufficient permissions' });
        }

        try {
          const resources = Object.entries(tableConfigs).map(([index, config]) => ({
            index,
            name: config.name,
            pk: config.pk
          }));
          return createResponse(200, { resources });
        } catch (error) {
          console.error('Error fetching resources:', error);
          return createResponse(500, { error: 'Internal server error' });
        }
      }
    }

    if (pathParts.length < 2 || pathParts[0] !== 'api') {
      return createResponse(404, { error: 'Not found' });
    }

    const tableIndex = pathParts[1];
    const tableConfig = getTableConfig(tableIndex);
    const isBulkOperation = pathParts[2] === 'bulk';
    const itemId = pathParts[2] && !isBulkOperation ? pathParts[2] : null;

    if (isBulkOperation && event.httpMethod === 'POST') {
      if (!hasPermission(user, tableConfig.name, 'bulk')) {
        return createResponse(403, { error: 'Insufficient permissions' });
      }

      if (!event.body) {
        return createResponse(400, { error: 'Request body is required' });
      }

      try {
        const { items } = JSON.parse(event.body);
        if (!Array.isArray(items)) {
          return createResponse(400, { error: 'items must be an array' });
        }

        const requiredFields = getRequiredFields(tableIndex);
        let imported = 0;
        let failed = 0;
        const errors: string[] = [];

        const chunks = [];
        for (let i = 0; i < items.length; i += 25) {
          chunks.push(items.slice(i, i + 25));
        }

        for (const chunk of chunks) {
          const putRequests = [];
          for (const item of chunk) {
            const validationErrors = validateRequired(item, requiredFields);
            if (validationErrors.length > 0) {
              failed++;
              errors.push(`Item validation failed: ${validationErrors.join(', ')}`);
              continue;
            }

            const now = new Date().toISOString();
            const id = item.id || randomUUID();
            
            putRequests.push({
              PutRequest: {
                Item: {
                  pk: tableConfig.pk,
                  sk: id,
                  id,
                  ...item,
                  createdAt: now,
                  updatedAt: now,
                  createdBy: user.id,
                  updatedBy: user.id
                }
              }
            });
          }

          if (putRequests.length > 0) {
            try {
              await docClient.send(new BatchWriteCommand({
                RequestItems: {
                  [TABLE_NAME]: putRequests
                }
              }));
              imported += putRequests.length;
            } catch (error) {
              failed += putRequests.length;
              errors.push(`Batch write failed: ${error}`);
            }
          }
        }

        await writeAuditLog('BULK_IMPORT', tableConfig.name, user.id, { imported, failed });
        return createResponse(200, { imported, failed, errors });
      } catch (error) {
        console.error('Bulk import error:', error);
        return createResponse(500, { error: 'Internal server error' });
      }
    }

    switch (event.httpMethod) {
      case 'GET':
        if (!hasPermission(user, tableConfig.name, 'read')) {
          return createResponse(403, { error: 'Insufficient permissions' });
        }

        if (itemId) {
          try {
            const result = await docClient.send(new GetCommand({
              TableName: TABLE_NAME,
              Key: { pk: tableConfig.pk, sk: itemId }
            }));
            
            if (!result.Item) {
              return createResponse(404, { error: 'Item not found' });
            }
            
            return createResponse(200, result.Item);
          } catch (error) {
            console.error('Get item error:', error);
            return createResponse(500, { error: 'Internal server error' });
          }
        } else {
          try {
            const result = await docClient.send(new ScanCommand({
              TableName: TABLE_NAME,
              FilterExpression: 'pk = :pk',
              ExpressionAttributeValues: { ':pk': tableConfig.pk }
            }));
            
            return createResponse(200, { items: result.Items || [] });
          } catch (error) {
            console.error('Scan error:', error);
            return createResponse(500, { error: 'Internal server error' });
          }
        }

      case 'POST':
        if (!hasPermission(user, tableConfig.name, 'create')) {
          return createResponse(403, { error: 'Insufficient permissions' });
        }

        if (!event.body) {
          return createResponse(400, { error: 'Request body is required' });
        }

        try {
          const data = JSON.parse(event.body);
          const requiredFields = getRequiredFields(tableIndex);
          const validationErrors = validateRequired(data, requiredFields);
          
          if (validationErrors.length > 0) {
            return createResponse(400, { error: 'Validation failed', details: validationErrors });
          }

          const now = new Date().toISOString();
          const id = data.id || randomUUID();
          
          const item = {
            pk: tableConfig.pk,
            sk: id,
            id,
            ...data,
            createdAt: now,
            updatedAt: now,
            createdBy: user.id,
            updatedBy: user.id
          };

          await docClient.send(new PutCommand({
            TableName: TABLE_NAME,
            Item: item
          }));

          await writeAuditLog('CREATE', tableConfig.name, user.id, { id });
          return createResponse(201, item);
        } catch (error) {
          console.error('Create error:', error);
          return createResponse(500, { error: 'Internal server error' });
        }

      case 'PUT':
        if (!itemId) {
          return createResponse(400, { error: 'Item ID is required for update' });
        }

        if (!hasPermission(user, tableConfig.name, 'update')) {
          return createResponse(403, { error: 'Insufficient permissions' });
        }

        if (!event.body) {
          return createResponse(400, { error: 'Request body is required' });
        }

        try {
          const data = JSON.parse(event.body);
          const requiredFields = getRequiredFields(tableIndex);
          const validationErrors = validateRequired(data, requiredFields);
          
          if (validationErrors.length > 0) {
            return createResponse(400, { error: 'Validation failed', details: validationErrors });
          }

          const existingItem = await docClient.send(new GetCommand({
            TableName: TABLE_NAME,
            Key: { pk: tableConfig.pk, sk: itemId }
          }));

          if (!existingItem.Item) {
            return createResponse(404, { error: 'Item not found' });
          }

          const now = new Date().toISOString();
          const updatedItem = {
            ...existingItem.Item,
            ...data,
            updatedAt: now,
            updatedBy: user.id
          };

          await docClient.send(new PutCommand({
            TableName: TABLE_NAME,
            Item: updatedItem
          }));

          await writeAuditLog('UPDATE', tableConfig.name, user.id, { id: itemId });
          return createResponse(200, updatedItem);
        } catch (error) {
          console.error('Update error:', error);
          return createResponse(500, { error: 'Internal server error' });
        }

      case 'DELETE':
        if (!itemId) {
          return createResponse(400, { error: 'Item ID is required for delete' });
        }

        if (!hasPermission(user, tableConfig.name, 'delete')) {
          return createResponse(403, { error: 'Insufficient permissions' });
        }

        try {
          const existingItem = await docClient.send(new GetCommand({
            TableName: TABLE_NAME,
            Key: { pk: tableConfig.pk, sk: itemId }
          }));

          if (!existingItem.Item) {
            return createResponse(404, { error: 'Item not found' });
          }

          await docClient.send(new DeleteCommand({
            TableName: TABLE_NAME,
            Key: { pk: tableConfig.pk, sk: itemId }
          }));

          await writeAuditLog('DELETE', tableConfig.name, user.id, { id: itemId });
          return createResponse(200, { message: 'Item deleted successfully' });
        } catch (error) {
          console.error('Delete error:', error);
          return createResponse(500, { error: 'Internal server error' });
        }

      default:
        return createResponse(405, { error: 'Method not allowed' });
    }
  } catch (error) {
    console.error('Handler error:', error);
    return createResponse(500, { error: 'Internal server error' });
  }
};