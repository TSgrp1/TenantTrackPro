# API Documentation

## Purchase Management API

### Purchase Forms

#### Create Purchase Request
```http
POST /submit-purchase-form
Content-Type: multipart/form-data
```

**Parameters:**
- `pr_number` (string): Purchase request number
- `request_date` (date): Date of request
- `category[]` (array): Categories selected
- `description[]` (array): Item descriptions
- `unit_cost[]` (array): Unit costs
- `quantity[]` (array): Quantities
- `total[]` (array): Total costs
- `dc_oe_signature` (string): Base64 signature data
- `operation_manager_signature` (string): Base64 signature data
- `general_manager_signature` (string): Base64 signature data

**Response:**
```json
{
  "success": true,
  "request_number": "PR-20240623-0001",
  "message": "Purchase form submitted successfully"
}
```

#### Get Purchase Request
```http
GET /api/purchase-request/{id}
```

**Response:**
```json
{
  "success": true,
  "request": {
    "id": 1,
    "request_number": "PR-20240623-0001",
    "request_date": "2024-06-23",
    "category": "Purchase Stock",
    "requested_by": "John Doe",
    "status": "Pending",
    "items": [
      {
        "description": "Office Chair",
        "unit_cost": 150.00,
        "quantity": 2,
        "total_cost": 300.00
      }
    ]
  }
}
```

#### Download Purchase Request PDF
```http
GET /api/purchase-request/{id}/pdf
```

Returns PDF file for download.

#### Delete Purchase Request
```http
DELETE /api/purchase-request/{id}
```

**Response:**
```json
{
  "success": true,
  "message": "Purchase request deleted successfully"
}
```

### Stock Management

#### Get Stock Items
```http
GET /api/stock-items
```

**Response:**
```json
{
  "success": true,
  "items": [
    {
      "id": 1,
      "name": "Office Chair",
      "description": "Ergonomic office chair"
    }
  ]
}
```

#### Create Stock Item
```http
POST /api/stock-items
Content-Type: multipart/form-data
```

**Parameters:**
- `name` (string): Item name
- `description` (string): Item description
- `category` (string): Item category
- `quantity` (integer): Quantity
- `status` (string): received/unreceived
- `location` (string): Storage location

**Response:**
```json
{
  "success": true,
  "message": "Stock item created successfully"
}
```

#### Get Stock Item
```http
GET /api/stock-items/{id}
```

**Response:**
```json
{
  "success": true,
  "item": {
    "id": 1,
    "name": "Office Chair",
    "description": "Ergonomic office chair",
    "category": "Furniture",
    "quantity": 10,
    "status": "received",
    "location": "Warehouse A"
  }
}
```

#### Update Stock Item
```http
PUT /api/stock-items/{id}
Content-Type: multipart/form-data
```

**Parameters:** Same as create

**Response:**
```json
{
  "success": true,
  "message": "Stock item updated successfully"
}
```

#### Delete Stock Item
```http
DELETE /api/stock-items/{id}
```

**Response:**
```json
{
  "success": true,
  "message": "Stock item deleted successfully"
}
```

## Authentication

All API endpoints require authentication. Include session cookie or authentication headers.

## Error Responses

All endpoints may return error responses:

```json
{
  "success": false,
  "error": "Error message here"
}
```

## Status Codes

- `200` - Success
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `500` - Internal Server Error

## Rate Limiting

No rate limiting currently implemented, but recommended for production:
- 100 requests per minute per user
- 1000 requests per hour per IP

## Pagination

For endpoints returning lists, pagination can be added:

```http
GET /api/stock-items?page=1&limit=20
```

## Filtering

Stock items support filtering:

```http
GET /api/stock-items?category=Furniture&status=received
```

## Sorting

Results can be sorted:

```http
GET /api/stock-items?sort=name&order=asc
```