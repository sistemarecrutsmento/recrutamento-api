'use strict';
const axios = require('axios');

const BASE_URL = (process.env.ASAAS_API_BASE || 'https://api.asaas.com/v3').replace(/\/$/, '');
const API_KEY = process.env.ASAAS_API_KEY || '';

function configurado() { return !!API_KEY; }

async function asaasRequest(method, path, data) {
  if (!API_KEY) throw new Error('ASAAS_API_KEY não configurada');
  const response = await axios({
    method, url: `${BASE_URL}${path}`, data,
    headers: { access_token: API_KEY, accept: 'application/json', 'content-type': 'application/json' },
    timeout: 20000, validateStatus: () => true
  });
  if (response.status < 200 || response.status >= 300) {
    const detail = response.data?.errors?.[0]?.description || response.data?.message || `HTTP ${response.status}`;
    const err = new Error(detail); err.status = response.status; throw err;
  }
  return response.data;
}

async function criarCliente({ name, email, cpfCnpj, phone }) {
  return asaasRequest('POST', '/customers', {
    name, email, cpfCnpj: cpfCnpj || undefined, phone: phone || undefined,
    notificationDisabled: false
  });
}

async function criarCheckoutRecorrente({ billingTypes = ['CREDIT_CARD'], customerData, item, nextDueDate, callback }) {
  return asaasRequest('POST', '/checkouts', {
    billingTypes, chargeTypes: ['RECURRENT'], minutesToExpire: 60,
    callback, items: [item], customerData,
    subscription: { cycle: 'MONTHLY', nextDueDate }
  });
}

async function criarAssinatura({ customer, billingType = 'UNDEFINED', value, nextDueDate, cycle = 'MONTHLY', description }) {
  return asaasRequest('POST', '/subscriptions', {
    customer, billingType, value, nextDueDate, cycle, description,
    notificationDisabled: false
  });
}

module.exports = { configurado, criarCliente, criarCheckoutRecorrente, criarAssinatura, BASE_URL };
