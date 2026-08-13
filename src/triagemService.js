const { completarJSON } = require('./iaService');
const {
  construirPromptTriagem,
  hashEntrada
} = require('./triagemPrompt');
const {
  validarAnalise,
  calcularScore
} = require('./triagemSchema');

const PROMPT_VERSION = 'triagem-v1';
const SCHEMA_VERSION = 'triagem-schema-v1';

async function analisarTriagem({ vaga, candidato, requisitos }) {
  const prompt = construirPromptTriagem({ vaga, candidato, requisitos });
  const resultadoBruto = await completarJSON({
    system: prompt.system,
    user: prompt.user,
    model: process.env.GROQ_MODEL || 'llama-3.1-8b-instant',
    temperature: 0,
    maxTokens: Number(process.env.TRIAGEM_IA_MAX_TOKENS || 5000)
  });

  if (!resultadoBruto) {
    const erro = new Error('A análise por IA está indisponível.');
    erro.code = 'TRIAGEM_IA_INDISPONIVEL';
    throw erro;
  }

  const validacao = validarAnalise(resultadoBruto);
  if (!validacao.valida) {
    const erro = new Error('A IA retornou uma análise inválida.');
    erro.code = 'TRIAGEM_RESULTADO_INVALIDO';
    erro.detalhes = validacao.erros;
    throw erro;
  }

  const score = calcularScore(validacao.resultado.requisitos);
  return {
    resultado: validacao.resultado,
    score,
    hash_entrada: hashEntrada(prompt.entrada),
    modelo: process.env.GROQ_MODEL || 'llama-3.1-8b-instant',
    versao_prompt: PROMPT_VERSION,
    versao_schema: SCHEMA_VERSION
  };
}

module.exports = {
  analisarTriagem,
  PROMPT_VERSION,
  SCHEMA_VERSION
};
