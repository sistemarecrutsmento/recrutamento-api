/**
 * Integração com Google Meet via Service Account + Domain-Wide Delegation
 *
 * Cria eventos no Google Calendar do admin (comercial@vagasio.com.br) que já vêm
 * com link do Meet anexado. Cada entrevista gera 1 link único.
 *
 * Autenticação: Service Account (vagasio-meet-bot) com DWD autorizada
 * Escopos: calendar.events, meetings.space.created
 *
 * build: 2026-07-25T20:50-forçar-redeploy
 */

const { google } = require('googleapis');
const path = require('path');

let _calendarClient = null;

/**
 * Cria (ou retorna cache) o cliente autenticado do Google Calendar
 * usando Service Account + impersonation (DWD).
 */
function getCalendarClient() {
  if (_calendarClient) return _calendarClient;

  const serviceAccountJson = process.env.GCP_SERVICE_ACCOUNT_JSON;
  const adminEmail = process.env.MEET_ADMIN_EMAIL || 'comercial@vagasio.com.br';

  if (!serviceAccountJson) {
    throw new Error('GCP_SERVICE_ACCOUNT_JSON não configurada. Coloque o conteúdo do JSON da Service Account na env var.');
  }

  let credentials;
  try {
    credentials = JSON.parse(serviceAccountJson);
  } catch (e) {
    throw new Error('GCP_SERVICE_ACCOUNT_JSON inválida (não é JSON parseável): ' + e.message);
  }

  const auth = new google.auth.JWT({
    email: credentials.client_email,
    key: credentials.private_key,
    scopes: [
      'https://www.googleapis.com/auth/calendar.events',
      'https://www.googleapis.com/auth/meetings.space.created',
    ],
    subject: adminEmail, // DWD: impersona o admin do Workspace
  });

  _calendarClient = google.calendar({ version: 'v3', auth });
  return _calendarClient;
}

/**
 * Cria um evento no Google Calendar do admin com link do Meet anexado.
 *
 * @param {object} params
 * @param {string} params.summary     - Título do evento (ex: "Entrevista RH - Fulano")
 * @param {string} params.description - Descrição longa
 * @param {Date|string} params.startTime - ISO string ou Date
 * @param {number} params.durationMinutes - Duração em minutos
 * @param {string[]} params.attendees  - Lista de e-mails (candidato, entrevistador)
 * @returns {Promise<{eventId: string, meetLink: string, htmlLink: string}>}
 */
async function criarEventoMeet({ summary, description, startTime, durationMinutes, attendees = [] }) {
  const calendar = getCalendarClient();

  const start = new Date(startTime);
  if (isNaN(start.getTime())) throw new Error('startTime inválido');

  const end = new Date(start.getTime() + (durationMinutes || 60) * 60 * 1000);

  const event = {
    summary,
    description,
    start: {
      dateTime: start.toISOString(),
      timeZone: 'America/Sao_Paulo',
    },
    end: {
      dateTime: end.toISOString(),
      timeZone: 'America/Sao_Paulo',
    },
    attendees: attendees.map(email => ({ email })),
    conferenceData: {
      createRequest: {
        requestId: `vagasio-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`,
        conferenceSolutionKey: { type: 'hangoutsMeet' },
      },
    },
    reminders: {
      useDefault: false,
      overrides: [
        { method: 'email', minutes: 24 * 60 }, // 1 dia antes
        { method: 'popup', minutes: 15 },       // 15 min antes
      ],
    },
  };

  const r = await calendar.events.insert({
    calendarId: 'primary',
    conferenceDataVersion: 1,
    sendUpdates: 'all', // envia e-mail pros participantes com o link do Meet
    requestBody: event,
  });

  const data = r.data;
  const meetLink = data.hangoutLink || (data.conferenceData?.entryPoints?.find(e => e.entryPointType === 'video')?.uri) || null;

  return {
    eventId: data.id,
    meetLink,
    htmlLink: data.htmlLink,
  };
}

/**
 * Atualiza um evento existente (ex: remar horário).
 */
async function atualizarEventoMeet({ eventId, summary, description, startTime, durationMinutes, attendees }) {
  const calendar = getCalendarClient();

  const patch = {};
  if (summary) patch.summary = summary;
  if (description !== undefined) patch.description = description;

  if (startTime) {
    const start = new Date(startTime);
    const end = new Date(start.getTime() + (durationMinutes || 60) * 60 * 1000);
    patch.start = { dateTime: start.toISOString(), timeZone: 'America/Sao_Paulo' };
    patch.end = { dateTime: end.toISOString(), timeZone: 'America/Sao_Paulo' };
  }

  if (attendees) patch.attendees = attendees.map(email => ({ email }));

  const r = await calendar.events.patch({
    calendarId: 'primary',
    eventId,
    conferenceDataVersion: 1,
    sendUpdates: 'all',
    requestBody: patch,
  });

  const data = r.data;
  const meetLink = data.hangoutLink || (data.conferenceData?.entryPoints?.find(e => e.entryPointType === 'video')?.uri) || null;

  return { eventId: data.id, meetLink, htmlLink: data.htmlLink };
}

/**
 * Deleta um evento do Calendar.
 */
async function deletarEventoMeet(eventId) {
  const calendar = getCalendarClient();
  await calendar.events.delete({
    calendarId: 'primary',
    eventId,
    sendUpdates: 'all',
  });
}

/**
 * Testa a conexão (lista 1 evento futuro do admin).
 */
async function testarConexao() {
  const calendar = getCalendarClient();
  const r = await calendar.events.list({
    calendarId: 'primary',
    maxResults: 1,
    timeMin: new Date().toISOString(),
    singleEvents: true,
    orderBy: 'startTime',
  });
  return { ok: true, total: r.data.items?.length || 0 };
}

module.exports = {
  criarEventoMeet,
  atualizarEventoMeet,
  deletarEventoMeet,
  testarConexao,
  getCalendarClient,
};