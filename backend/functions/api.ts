import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, ScanCommand, GetCommand, PutCommand, UpdateCommand, DeleteCommand, BatchWriteCommand } from '@aws-sdk/lib-dynamodb';
import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { User, checkPermission } from './rbac';
import { randomUUID } from 'crypto';

const client = new DynamoDBClient({});
const docClient = DynamoDBDocumentClient.from(client);
const TABLE_NAME = process.env.MAIN_TABLE!;

interface TableConfig {
  pk: string;
  name: string;
  idField: string;
}

const TABLES: Record<string, TableConfig> = {
  '0': { pk: 'USER', name: 'ユーザー', idField: 'ユーザーID' },
  '1': { pk: 'PRODUCT', name: '製品マスタ', idField: '製品ID' },
  '2': { pk: 'PRODUCT_SPEC', name: '製品仕様', idField: '仕様ID' },
  '3': { pk: 'PROCESS', name: '工程マスタ', idField: '工程ID' },
  '4': { pk: 'PRODUCTION_LINE', name: '製造ライン', idField: 'ライン_ID' },
  '5': { pk: 'MATERIAL', name: '資材マスタ', idField: '資材ID' },
  '6': { pk: 'STANDARD_PROCEDURE', name: '標準手順書', idField: '手順書ID' },
  '7': { pk: 'QUALITY_STANDARD', name: '品質基準', idField: '品質基準ID' },
  '8': { pk: 'PRODUCTION_ORDER', name: '生産指示書', idField: '生産指示書ID' },
  '9': { pk: 'PRODUCTION_RESULT', name: '生産実績', idField: '生産実績ID' },
  '10': { pk: 'WORK_HISTORY', name: '作業履歴', idField: '作業履歴ID' },
  '11': { pk: 'QUALITY_INSPECTION', name: '品質検査結果', idField: '検査結果ID' },
  '12': { pk: 'PROGRESS_MANAGEMENT', name: '進捗管理', idField: '進捗管理ID' },
  '13': { pk: 'ALERT_NOTIFICATION', name: 'アラート通知履歴', idField: 'アラート通知履歴ID' },
  '14': { pk: 'ANOMALY_DETECTION', name: '異常値検出ログ', idField: '異常値検出ID' }
};

function getCurrentUser(event: APIGatewayProxyEvent): User {
  const authHeader = event.headers.Authorization || event.headers.authorization;
  if (!authHeader) {
    throw new Error('Authorization header required');
  }
  
  try {
    const token = authHeader.replace('Bearer ', '');
    const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
    return {
      id: payload.sub || 'unknown',
      role: payload.role || 'viewer'
    };
  } catch {
    return { id: 'anonymous', role: 'viewer' };
  }
}

function createResponse(statusCode: number, body: any): APIGatewayProxyResult {
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

async function writeAuditLog(action: string, resource: string, userId: string, details?: any): Promise<void> {
  const auditLog = {
    pk: 'AUDIT',
    sk: `${Date.now()}_${randomUUID()}`,
    action,
    resource,
    userId,
    timestamp: new Date().toISOString(),
    details: details || {}
  };
  
  await docClient.send(new PutCommand({
    TableName: TABLE_NAME,
    Item: auditLog
  }));
}

function validateRequired(item: any, requiredFields: string[]): string[] {
  const errors: string[] = [];
  for (const field of requiredFields) {
    if (!item[field]) {
      errors.push(`${field} is required`);
    }
  }
  return errors;
}

function getRequiredFields(tableIndex: string): string[] {
  const fieldMap: Record<string, string[]> = {
    '0': ['ユーザー名', 'パスワードハッシュ', '氏名', '権限レベル', '有効フラグ'],
    '1': ['製品コード', '製品名', '製品分類', '単位', '有効フラグ'],
    '2': ['製品ID', '仕様バージョン', '仕様名', '有効開始日', '承認状態'],
    '3': ['工程コード', '工程名', '工程区分', '有効フラグ'],
    '4': ['ライン_コード', 'ライン_名', '工場_コード', '稼働_状態', '有効_フラグ'],
    '5': ['資材コード', '資材名', '資材分類', '単位', '有効フラグ'],
    '6': ['手順書コード', '手順書名', '製品ID', '工程ID', 'バージョン', '手順内容', '有効フラグ', '承認状態'],
    '7': ['基準名', '検査項目', '重要度', '有効フラグ', '適用開始日'],
    '8': ['生産指示書番号', '製品ID', '製品仕様ID', '製造ラインID', '生産数量', '優先度', '生産開始予定日時', '生産完了予定日時', 'ステータス'],
    '9': ['生産指示書ID', '製品ID', '製造ラインID', '工程ID', '生産開始日時', '計画数量', '実績数量', '良品数量', '不良品数量', 'ステータス'],
    '10': ['生産指示書ID', '工程ID', '製造ラインID', '作業者ID', '作業開始日時', '作業ステータス'],
    '11': ['生産実績ID', '品質基準ID', '検査日時', '検査者ID', '検査工程ID', '検査ロット番号', '検査数量', '合格数量', '不合格数量', '総合判定'],
    '12': ['生産指示書ID', '工程ID', '製造ラインID', '計画開始日時', '計画終了日時', '計画数量', '完了数量', '進捗率', 'ステータス', '遅延フラグ'],
    '13': ['アラート種別', 'アラートレベル', 'アラート内容', '通知先ユーザーID', '通知方法', '通知状態', '通知送信日時', '対応完了フラグ'],
    '14': ['製造ラインID', '工程ID', '検出項目名', '検出値', '異常レベル', '検出日時', '対応状況', 'アラート送信済']
  };
  return fieldMap[tableIndex] || [];
}

export const handler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
  try {
    if (event.httpMethod === 'OPTIONS') {
      return createResponse(200, {});
    }

    const user = getCurrentUser(event);
    const path = event.path;
    const method = event.httpMethod;
    
    // GET /resources - リソース一覧取得
    if (path === '/resources' && method === 'GET') {
      checkPermission(user, 'resources', 'read');
      
      const resources = Object.entries(TABLES).map(([index, config]) => ({
        index,
        pk: config.pk,
        name: config.name,
        idField: config.idField
      }));
      
      return createResponse(200, { resources });
    }

    // テーブル操作のパスパターン解析
    const tableMatch = path.match(/^\/api\/(\d+)(?:\/(\w+))?(?:\/(\w+))?$/);
    if (!tableMatch) {
      return createResponse(404, { error: 'Endpoint not found' });
    }

    const [, tableIndex, operation, itemId] = tableMatch;
    const tableConfig = TABLES[tableIndex];
    
    if (!tableConfig) {
      return createResponse(404, { error: 'Table not found' });
    }

    // 一括インポート処理
    if (operation === 'bulk' && method === 'POST') {
      checkPermission(user, tableConfig.pk, 'bulk');
      
      const body = JSON.parse(event.body || '{}');
      const items = body.items || [];
      
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
        const writeRequests = [];
        
        for (const item of batch) {
          try {
            const requiredFields = getRequiredFields(tableIndex);
            const validationErrors = validateRequired(item, requiredFields);
            
            if (validationErrors.length > 0) {
              errors.push(`Item ${i + writeRequests.length + 1}: ${validationErrors.join(', ')}`);
              failed++;
              continue;
            }
            
            const processedItem = {
              ...item,
              pk: tableConfig.pk,
              sk: item[tableConfig.idField] || randomUUID(),
              [tableConfig.idField]: item[tableConfig.idField] || randomUUID(),
              作成日時: item.作成日時 || now,
              更新日時: now,
              作成者: item.作成者 || user.id,
              更新者: user.id
            };
            
            writeRequests.push({
              PutRequest: {
                Item: processedItem
              }
            });
          } catch (error) {
            errors.push(`Item ${i + writeRequests.length + 1}: ${error}`);
            failed++;
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
            errors.push(`Batch write error: ${error}`);
          }
        }
      }
      
      await writeAuditLog('BULK_IMPORT', tableConfig.pk, user.id, { imported, failed, total: items.length });
      
      return createResponse(200, { imported, failed, errors });
    }

    // 一覧取得
    if (method === 'GET' && !itemId) {
      checkPermission(user, tableConfig.pk, 'read');
      
      const result = await docClient.send(new ScanCommand({
        TableName: TABLE_NAME,
        FilterExpression: 'pk = :pk',
        ExpressionAttributeValues: {
          ':pk': tableConfig.pk
        }
      }));
      
      return createResponse(200, { items: result.Items || [] });
    }

    // 詳細取得
    if (method === 'GET' && itemId) {
      checkPermission(user, tableConfig.pk, 'read');
      
      const result = await docClient.send(new GetCommand({
        TableName: TABLE_NAME,
        Key: {
          pk: tableConfig.pk,
          sk: itemId
        }
      }));
      
      if (!result.Item) {
        return createResponse(404, { error: 'Item not found' });
      }
      
      return createResponse(200, result.Item);
    }

    // 新規作成
    if (method === 'POST' && !itemId) {
      checkPermission(user, tableConfig.pk, 'create');
      
      const body = JSON.parse(event.body || '{}');
      const requiredFields = getRequiredFields(tableIndex);
      const validationErrors = validateRequired(body, requiredFields);
      
      if (validationErrors.length > 0) {
        return createResponse(400, { error: 'Validation failed', details: validationErrors });
      }
      
      const now = new Date().toISOString();
      const id = randomUUID();
      
      const item = {
        ...body,
        pk: tableConfig.pk,
        sk: id,
        [tableConfig.idField]: id,
        作成日時: now,
        更新日時: now,
        作成者: user.id,
        更新者: user.id
      };
      
      await docClient.send(new PutCommand({
        TableName: TABLE_NAME,
        Item: item
      }));
      
      await writeAuditLog('CREATE', tableConfig.pk, user.id, { id });
      
      return createResponse(201, item);
    }

    // 更新
    if (method === 'PUT' && itemId) {
      checkPermission(user, tableConfig.pk, 'update');
      
      const body = JSON.parse(event.body || '{}');
      
      // 既存アイテムの確認
      const existing = await docClient.send(new GetCommand({
        TableName: TABLE_NAME,
        Key: {
          pk: tableConfig.pk,
          sk: itemId
        }
      }));
      
      if (!existing.Item) {
        return createResponse(404, { error: 'Item not found' });
      }
      
      const now = new Date().toISOString();
      const updatedItem = {
        ...existing.Item,
        ...body,
        pk: tableConfig.pk,
        sk: itemId,
        [tableConfig.idField]: itemId,
        更新日時: now,
        更新者: user.id
      };
      
      await docClient.send(new PutCommand({
        TableName: TABLE_NAME,
        Item: updatedItem
      }));
      
      await writeAuditLog('UPDATE', tableConfig.pk, user.id, { id: itemId });
      
      return createResponse(200, updatedItem);
    }

    // 削除
    if (method === 'DELETE' && itemId) {
      checkPermission(user, tableConfig.pk, 'delete');
      
      // 既存アイテムの確認
      const existing = await docClient.send(new GetCommand({
        TableName: TABLE_NAME,
        Key: {
          pk: tableConfig.pk,
          sk: itemId
        }
      }));
      
      if (!existing.Item) {
        return createResponse(404, { error: 'Item not found' });
      }
      
      await docClient.send(new DeleteCommand({
        TableName: TABLE_NAME,
        Key: {
          pk: tableConfig.pk,
          sk: itemId
        }
      }));
      
      await writeAuditLog('DELETE', tableConfig.pk, user.id, { id: itemId });
      
      return createResponse(200, { message: 'Item deleted successfully' });
    }

    return createResponse(405, { error: 'Method not allowed' });
    
  } catch (error: any) {
    console.error('Error:', error);
    
    if (error.message.includes('Access denied')) {
      return createResponse(403, { error: error.message });
    }
    
    if (error.message.includes('Authorization header required')) {
      return createResponse(401, { error: 'Unauthorized' });
    }
    
    if (error.message.includes('Validation failed')) {
      return createResponse(400, { error: error.message });
    }
    
    return createResponse(500, { error: 'Internal server error' });
  }
};