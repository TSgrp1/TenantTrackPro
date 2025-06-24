/* TS Management Services - Main JavaScript */
/* Static file organization - June 24, 2025 */

// Global Application JavaScript Functions

// Bootstrap Dropdown Toggle Handler
document.addEventListener('DOMContentLoaded', function() {
    // Initialize Bootstrap dropdowns
    var dropdownElementList = [].slice.call(document.querySelectorAll('.dropdown-toggle'));
    var dropdownList = dropdownElementList.map(function (dropdownToggleEl) {
        return new bootstrap.Dropdown(dropdownToggleEl);
    });
    
    // Auto-hide alerts after 5 seconds
    setTimeout(function() {
        var alerts = document.querySelectorAll('.alert');
        alerts.forEach(function(alert) {
            if (alert.classList.contains('alert-dismissible')) {
                var bsAlert = new bootstrap.Alert(alert);
                bsAlert.close();
            }
        });
    }, 5000);
});

// Form Validation Functions
function validateForm(formId) {
    const form = document.getElementById(formId);
    if (!form) return false;
    
    const requiredFields = form.querySelectorAll('[required]');
    let isValid = true;
    
    requiredFields.forEach(function(field) {
        if (!field.value.trim()) {
            field.classList.add('is-invalid');
            isValid = false;
        } else {
            field.classList.remove('is-invalid');
        }
    });
    
    return isValid;
}

// Loading State Functions
function showLoading(buttonId) {
    const button = document.getElementById(buttonId);
    if (button) {
        button.disabled = true;
        button.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Loading...';
    }
}

function hideLoading(buttonId, originalText) {
    const button = document.getElementById(buttonId);
    if (button) {
        button.disabled = false;
        button.innerHTML = originalText;
    }
}

// Modal Functions
function showModal(modalId) {
    const modal = new bootstrap.Modal(document.getElementById(modalId));
    modal.show();
}

function hideModal(modalId) {
    const modal = bootstrap.Modal.getInstance(document.getElementById(modalId));
    if (modal) {
        modal.hide();
    }
}

// Table Functions
function sortTable(columnIndex, tableId) {
    const table = document.getElementById(tableId);
    if (!table) return;
    
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    
    rows.sort((a, b) => {
        const aText = a.cells[columnIndex].textContent.trim();
        const bText = b.cells[columnIndex].textContent.trim();
        return aText.localeCompare(bText);
    });
    
    rows.forEach(row => tbody.appendChild(row));
}

// Search Functions
function filterTable(searchInput, tableId) {
    const filter = searchInput.value.toLowerCase();
    const table = document.getElementById(tableId);
    if (!table) return;
    
    const rows = table.querySelectorAll('tbody tr');
    
    rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(filter) ? '' : 'none';
    });
}

// Date Formatting Functions
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-SG', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
    });
}

function formatDateTime(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString('en-SG', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

// File Upload Functions
function handleFileUpload(inputElement, maxSizeMB = 5) {
    const file = inputElement.files[0];
    if (!file) return false;
    
    const maxSize = maxSizeMB * 1024 * 1024; // Convert to bytes
    
    if (file.size > maxSize) {
        alert(`File size must be less than ${maxSizeMB}MB`);
        inputElement.value = '';
        return false;
    }
    
    return true;
}

// QR Code Functions
function downloadQR(qrId, filename = 'qrcode.png') {
    const canvas = document.getElementById(qrId);
    if (!canvas) return;
    
    const link = document.createElement('a');
    link.download = filename;
    link.href = canvas.toDataURL();
    link.click();
}

// Print Functions
function printPage() {
    window.print();
}

function printElement(elementId) {
    const element = document.getElementById(elementId);
    if (!element) return;
    
    const printWindow = window.open('', '_blank');
    printWindow.document.write(`
        <html>
            <head>
                <title>Print</title>
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
                <style>
                    body { font-family: Arial, sans-serif; }
                    @media print { body { margin: 0; } }
                </style>
            </head>
            <body>
                ${element.innerHTML}
            </body>
        </html>
    `);
    printWindow.document.close();
    printWindow.print();
}

// Export Functions
function exportTableToCSV(tableId, filename = 'export.csv') {
    const table = document.getElementById(tableId);
    if (!table) return;
    
    const rows = table.querySelectorAll('tr');
    const csvContent = Array.from(rows).map(row => {
        const cells = row.querySelectorAll('th, td');
        return Array.from(cells).map(cell => {
            return '"' + cell.textContent.replace(/"/g, '""') + '"';
        }).join(',');
    }).join('\n');
    
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = filename;
    link.click();
}

// Navigation Functions
function goBack() {
    window.history.back();
}

function redirectTo(url) {
    window.location.href = url;
}

// Local Storage Functions
function saveToLocalStorage(key, value) {
    try {
        localStorage.setItem(key, JSON.stringify(value));
        return true;
    } catch (e) {
        console.error('Failed to save to localStorage:', e);
        return false;
    }
}

function getFromLocalStorage(key) {
    try {
        const item = localStorage.getItem(key);
        return item ? JSON.parse(item) : null;
    } catch (e) {
        console.error('Failed to get from localStorage:', e);
        return null;
    }
}

// Notification Functions
function showNotification(message, type = 'info') {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
    alertDiv.style.cssText = 'top: 20px; right: 20px; z-index: 9999; max-width: 400px;';
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.body.appendChild(alertDiv);
    
    setTimeout(() => {
        if (alertDiv.parentNode) {
            alertDiv.parentNode.removeChild(alertDiv);
        }
    }, 5000);
}

// AJAX Helper Functions
function makeRequest(url, method = 'GET', data = null) {
    return fetch(url, {
        method: method,
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
        },
        body: data ? JSON.stringify(data) : null
    }).then(response => {
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
    });
}

// Purchase Form Specific Functions (moved from purchase.js)
function addItem() {
    const table = document.getElementById('itemsTable').getElementsByTagName('tbody')[0];
    const rowCount = table.rows.length;
    const newRow = table.insertRow(rowCount);
    
    newRow.innerHTML = `
        <td><input type="text" class="form-control" name="items[${rowCount}][description]" required></td>
        <td><input type="number" class="form-control" name="items[${rowCount}][quantity]" min="1" required></td>
        <td><input type="number" class="form-control" name="items[${rowCount}][unit_price]" step="0.01" min="0" required onchange="calculateTotal()"></td>
        <td><span class="total-price">0.00</span></td>
        <td><button type="button" class="btn btn-danger btn-sm" onclick="removeItem(this)">Remove</button></td>
    `;
}

function removeItem(button) {
    const row = button.closest('tr');
    row.remove();
    calculateTotal();
    updateItemIndexes();
}

function calculateTotal() {
    const rows = document.querySelectorAll('#itemsTable tbody tr');
    let grandTotal = 0;
    
    rows.forEach(row => {
        const quantity = parseFloat(row.querySelector('input[name*="[quantity]"]').value) || 0;
        const unitPrice = parseFloat(row.querySelector('input[name*="[unit_price]"]').value) || 0;
        const total = quantity * unitPrice;
        
        row.querySelector('.total-price').textContent = total.toFixed(2);
        grandTotal += total;
    });
    
    document.getElementById('grandTotal').textContent = grandTotal.toFixed(2);
}

function updateItemIndexes() {
    const rows = document.querySelectorAll('#itemsTable tbody tr');
    rows.forEach((row, index) => {
        const inputs = row.querySelectorAll('input');
        inputs.forEach(input => {
            const name = input.name;
            const newName = name.replace(/\[\d+\]/, `[${index}]`);
            input.name = newName;
        });
    });
}

// Initialize application
document.addEventListener('DOMContentLoaded', function() {
    // Add any initialization code here
    console.log('TS Management System - JavaScript loaded');
});