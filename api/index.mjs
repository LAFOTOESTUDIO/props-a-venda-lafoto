// Função do Neon (projeto props-lafoto) que liga a página ao banco. Sem dependências.
// Público:   GET  /estado     -> quantas unidades restam de cada item (sem valores)
//            GET  /tem-senha  -> se a senha do painel já foi criada
// Com senha: POST /entrar, /painel, /venda, /desfazer, /estoque
// Uma vez só: POST /criar-senha, enquanto nenhuma senha existe.
// A senha nunca fica aqui: o banco guarda só o hash (tabela painel).
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

const URL_SQL = "https://" + new URL(process.env.DATABASE_URL).hostname.replace(/^[^.]+\./, "api.") + "/sql";
async function sql(query, params = []) {
  const r = await fetch(URL_SQL, {
    method: "POST",
    headers: { "Neon-Connection-String": process.env.DATABASE_URL, "Content-Type": "application/json" },
    body: JSON.stringify({ query, params }),
  });
  const d = await r.json();
  if (!r.ok) throw new Error(d.message || "erro no banco");
  return d.rows;
}

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};
const json = (dado, status = 200) =>
  new Response(JSON.stringify(dado), { status, headers: { ...CORS, "Content-Type": "application/json" } });

// trava simples contra chute de senha: 8 erros por IP a cada 15 minutos
const erros = new Map();
const JANELA = 15 * 60e3;
function bloqueado(ip) {
  const e = erros.get(ip);
  if (!e || Date.now() - e.desde > JANELA) { erros.delete(ip); return false; }
  return e.n >= 8;
}
function errou(ip) {
  const e = erros.get(ip);
  if (!e || Date.now() - e.desde > JANELA) erros.set(ip, { n: 1, desde: Date.now() });
  else e.n++;
}

const hashDe = (salt, senha) => createHash("sha256").update(salt + senha).digest("hex");
async function lerSenha() { return (await sql("SELECT hash, salt FROM painel WHERE id = 1"))[0] || null; }
async function senhaOk(senha) {
  const cfg = await lerSenha();
  if (typeof senha !== "string" || !cfg) return false;
  const a = Buffer.from(hashDe(cfg.salt, senha), "hex"), b = Buffer.from(cfg.hash, "hex");
  return a.length === b.length && timingSafeEqual(a, b);
}

async function painel() {
  const itens = await sql("SELECT id, nome, estoque AS restam FROM itens ORDER BY nome");
  const vendas = await sql(
    `SELECT v.id, v.item_id, i.nome, v.quantidade, v.valor, v.obs, v.criado_em
       FROM vendas v JOIN itens i ON i.id = v.item_id ORDER BY v.criado_em DESC LIMIT 200`);
  return { itens, vendas };
}

async function rotear(req) {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
  const rota = new URL(req.url).pathname.replace(/\/+$/, "") || "/";

  if (req.method === "GET" && rota === "/estado")
    return json({ itens: await sql("SELECT id, estoque AS restam FROM itens") });
  if (req.method === "GET" && rota === "/tem-senha") return json({ tem: !!(await lerSenha()) });
  if (req.method !== "POST") return json({ erro: "rota não encontrada" }, 404);

  const ip = req.headers.get("x-forwarded-for")?.split(",")[0].trim() || "?";
  if (bloqueado(ip)) return json({ erro: "Muitas tentativas. Espere 15 minutos." }, 429);
  let corpo;
  try { corpo = await req.json(); } catch { return json({ erro: "Pedido inválido." }, 400); }

  if (rota === "/criar-senha") {
    if (typeof corpo.senha !== "string" || corpo.senha.length < 8)
      return json({ erro: "A senha precisa de pelo menos 8 caracteres." }, 400);
    const salt = randomBytes(16).toString("hex");
    const r = await sql("INSERT INTO painel (id, hash, salt) VALUES (1, $1, $2) ON CONFLICT (id) DO NOTHING RETURNING id",
      [hashDe(salt, corpo.senha), salt]);
    if (!r.length) return json({ erro: "A senha já foi criada." }, 409);
    return json(await painel());
  }

  if (!(await senhaOk(corpo.senha))) { errou(ip); return json({ erro: "Senha errada." }, 401); }
  erros.delete(ip);

  if (rota === "/entrar" || rota === "/painel") return json(await painel());

  if (rota === "/venda") {
    const qtd = parseInt(corpo.quantidade, 10);
    const valor = corpo.valor === "" || corpo.valor == null ? null : Number(corpo.valor);
    if (!(qtd > 0) || (valor !== null && !(valor >= 0))) return json({ erro: "Quantidade ou valor inválido." }, 400);
    // baixa o estoque e registra a venda num comando só: ou as duas coisas acontecem, ou nenhuma
    const r = await sql(
      `WITH baixa AS (UPDATE itens SET estoque = estoque - $2, atualizado_em = now()
                        WHERE id = $1 AND estoque >= $2 RETURNING id)
       INSERT INTO vendas (item_id, quantidade, valor, obs) SELECT id, $2, $3, $4 FROM baixa RETURNING id`,
      [corpo.item_id, qtd, valor, String(corpo.obs || "").slice(0, 300) || null]);
    if (!r.length) return json({ erro: "Não tem essa quantidade disponível." }, 409);
    return json(await painel());
  }

  if (rota === "/desfazer") {
    await sql(
      `WITH apagada AS (DELETE FROM vendas WHERE id = $1 RETURNING item_id, quantidade)
       UPDATE itens i SET estoque = i.estoque + a.quantidade, atualizado_em = now()
         FROM apagada a WHERE i.id = a.item_id`, [parseInt(corpo.venda_id, 10)]);
    return json(await painel());
  }

  if (rota === "/estoque") {
    const n = parseInt(corpo.estoque, 10);
    if (!(n >= 0)) return json({ erro: "Quantidade inválida." }, 400);
    await sql("UPDATE itens SET estoque = $2, atualizado_em = now() WHERE id = $1", [corpo.item_id, n]);
    return json(await painel());
  }

  return json({ erro: "rota não encontrada" }, 404);
}

export default {
  async fetch(req) {
    try { return await rotear(req); }
    catch (e) { console.error(e); return json({ erro: "Falha no servidor. Tente de novo." }, 500); }
  },
};
