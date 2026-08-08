#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const https = require('node:https');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const SKILL_NAME = 'avoiding-macos-junk-files';
const MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024;
const RELEASES = Object.freeze({
  '1.1.0': Object.freeze({
    url: 'https://github.com/houyuxi012/houyuxi-skills/releases/download/v1.1.0/macOS.skill.zip',
    sha256: '8b1adc5307b087de4f2595fdf4ea1d2aa9d2ed73a5f3f43c49f9efba8f921a30',
  }),
});

function usage() {
  return `用法：
  npx @houyuxi/skills add ${SKILL_NAME} [选项]

选项：
  --target codex|claude|both  安装目标，默认 both
  --version <版本>            发布版本，默认最新受支持版本
  --force                     替换已有同名 Skill（原目录会原子替换）
  --dry-run                   仅显示将执行的操作
  -h, --help                  显示帮助
`;
}

function latestVersion() {
  return Object.keys(RELEASES).sort((left, right) => right.localeCompare(left, undefined, { numeric: true }))[0];
}

function parseArguments(argv) {
  if (argv.length === 0 || argv.includes('-h') || argv.includes('--help')) {
    return { help: true };
  }
  if (argv[0] !== 'add' || argv[1] !== SKILL_NAME) {
    throw new Error(`仅支持：add ${SKILL_NAME}`);
  }

  const options = { target: 'both', version: latestVersion(), force: false, dryRun: false };
  for (let index = 2; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--force') {
      options.force = true;
    } else if (argument === '--dry-run') {
      options.dryRun = true;
    } else if (argument === '--target' || argument === '--version') {
      const value = argv[index + 1];
      if (!value || value.startsWith('-')) {
        throw new Error(`${argument} 需要一个值`);
      }
      options[argument === '--target' ? 'target' : 'version'] = value;
      index += 1;
    } else {
      throw new Error(`不支持的参数：${argument}`);
    }
  }

  if (!['codex', 'claude', 'both'].includes(options.target)) {
    throw new Error('--target 只能是 codex、claude 或 both');
  }
  if (!Object.hasOwn(RELEASES, options.version)) {
    throw new Error(`不支持的版本：${options.version}`);
  }
  return options;
}

function targetDirectories(target, homeDirectory = os.homedir()) {
  const directories = [];
  if (target === 'codex' || target === 'both') {
    directories.push({ platform: 'Codex', directory: path.join(homeDirectory, '.codex', 'skills', SKILL_NAME) });
  }
  if (target === 'claude' || target === 'both') {
    directories.push({ platform: 'Claude Code', directory: path.join(homeDirectory, '.claude', 'skills', SKILL_NAME) });
  }
  return directories;
}

function sha256File(filePath) {
  const hash = crypto.createHash('sha256');
  const descriptor = fs.openSync(filePath, 'r');
  try {
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let bytesRead;
    let position = 0;
    do {
      bytesRead = fs.readSync(descriptor, buffer, 0, buffer.length, position);
      if (bytesRead > 0) {
        hash.update(buffer.subarray(0, bytesRead));
        position += bytesRead;
      }
    } while (bytesRead > 0);
  } finally {
    fs.closeSync(descriptor);
  }
  return hash.digest('hex');
}

function isSafeArchiveEntry(entry) {
  const normalized = entry.replaceAll('\\\\', '/');
  return normalized.length > 0
    && !normalized.startsWith('/')
    && !normalized.split('/').includes('..');
}

function verifyArchiveLayout(archivePath) {
  const entries = execFileSync('/usr/bin/unzip', ['-Z1', archivePath], { encoding: 'utf8' })
    .split(/\r?\n/)
    .filter(Boolean);
  if (!entries.includes('SKILL.md') || entries.some((entry) => !isSafeArchiveEntry(entry))) {
    throw new Error('发行包目录结构无效');
  }
}

function validateExtractedSkill(directory) {
  const skillDocument = path.join(directory, 'SKILL.md');
  if (!fs.statSync(skillDocument).isFile()) {
    throw new Error('发行包缺少 SKILL.md');
  }
  const walk = (current) => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const entryPath = path.join(current, entry.name);
      if (entry.isSymbolicLink() || !(entry.isDirectory() || entry.isFile())) {
        throw new Error(`发行包包含不支持的文件类型：${entryPath}`);
      }
      if (entry.isDirectory()) {
        walk(entryPath);
      }
    }
  };
  walk(directory);
}

function requestDownload(url, destination, redirectCount = 0) {
  return new Promise((resolve, reject) => {
    if (redirectCount > 5) {
      reject(new Error('下载重定向次数过多'));
      return;
    }
    const requestUrl = new URL(url);
    if (requestUrl.protocol !== 'https:') {
      reject(new Error('仅允许 HTTPS 发行包地址'));
      return;
    }
    const request = https.get(requestUrl, { headers: { 'User-Agent': '@houyuxi/skills installer' } }, (response) => {
      if ([301, 302, 303, 307, 308].includes(response.statusCode)) {
        const location = response.headers.location;
        response.resume();
        if (!location) {
          reject(new Error('下载重定向缺少目标地址'));
          return;
        }
        requestDownload(new URL(location, requestUrl).toString(), destination, redirectCount + 1).then(resolve, reject);
        return;
      }
      if (response.statusCode !== 200) {
        response.resume();
        reject(new Error(`下载失败，HTTP ${response.statusCode}`));
        return;
      }

      let received = 0;
      const output = fs.createWriteStream(destination, { flags: 'wx', mode: 0o600 });
      response.on('data', (chunk) => {
        received += chunk.length;
        if (received > MAX_DOWNLOAD_BYTES) {
          request.destroy(new Error('发行包超过大小限制'));
        }
      });
      output.on('error', reject);
      response.on('error', reject);
      output.on('finish', () => output.close(resolve));
      response.pipe(output);
    });
    request.setTimeout(30_000, () => request.destroy(new Error('下载超时')));
    request.on('error', reject);
  });
}

function assertDestination(destination, force) {
  if (!fs.existsSync(destination)) {
    return;
  }
  const metadata = fs.lstatSync(destination);
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
    throw new Error(`拒绝替换非目录或符号链接目标：${destination}`);
  }
  if (!force) {
    throw new Error(`已存在：${destination}；如需替换请使用 --force`);
  }
}

function createCandidateName(destination, suffix) {
  return `${destination}.${suffix}-${process.pid}-${crypto.randomBytes(8).toString('hex')}`;
}

function installAtomically(stagedSkill, destinations, force) {
  const candidates = [];
  const backups = [];
  const installed = [];
  try {
    for (const destination of destinations) {
      assertDestination(destination.directory, force);
      fs.mkdirSync(path.dirname(destination.directory), { recursive: true, mode: 0o755 });
    }
    for (const destination of destinations) {
      const candidate = createCandidateName(destination.directory, 'incoming');
      fs.cpSync(stagedSkill, candidate, { recursive: true, dereference: false, errorOnExist: true });
      candidates.push({ destination: destination.directory, candidate });
    }
    for (const item of candidates) {
      if (fs.existsSync(item.destination)) {
        const backup = createCandidateName(item.destination, 'backup');
        fs.renameSync(item.destination, backup);
        backups.push({ destination: item.destination, backup });
      }
      fs.renameSync(item.candidate, item.destination);
      installed.push(item.destination);
    }
  } catch (error) {
    for (const destination of installed.reverse()) {
      fs.rmSync(destination, { recursive: true, force: true });
    }
    for (const item of backups.reverse()) {
      if (fs.existsSync(item.backup) && !fs.existsSync(item.destination)) {
        fs.renameSync(item.backup, item.destination);
      }
    }
    throw error;
  } finally {
    for (const item of candidates) {
      fs.rmSync(item.candidate, { recursive: true, force: true });
    }
    for (const item of backups) {
      fs.rmSync(item.backup, { recursive: true, force: true });
    }
  }
}

async function install(options, homeDirectory = os.homedir()) {
  const destinations = targetDirectories(options.target, homeDirectory);
  if (options.dryRun) {
    return destinations;
  }
  for (const destination of destinations) {
    assertDestination(destination.directory, options.force);
  }

  const release = RELEASES[options.version];
  const temporaryRoot = await fsp.mkdtemp(path.join(os.tmpdir(), 'houyuxi-skills-'));
  try {
    const archivePath = path.join(temporaryRoot, `${SKILL_NAME}.zip`);
    await requestDownload(release.url, archivePath);
    if (sha256File(archivePath) !== release.sha256) {
      throw new Error('发行包 SHA-256 校验失败，已拒绝安装');
    }
    verifyArchiveLayout(archivePath);
    const extractedSkill = path.join(temporaryRoot, SKILL_NAME);
    fs.mkdirSync(extractedSkill, { mode: 0o700 });
    execFileSync('/usr/bin/unzip', ['-qq', archivePath, '-d', extractedSkill], { stdio: 'pipe' });
    validateExtractedSkill(extractedSkill);
    installAtomically(extractedSkill, destinations, options.force);
    return destinations;
  } finally {
    fs.rmSync(temporaryRoot, { recursive: true, force: true });
  }
}

async function main(argv = process.argv.slice(2)) {
  try {
    const options = parseArguments(argv);
    if (options.help) {
      process.stdout.write(usage());
      return 0;
    }
    const destinations = await install(options);
    const action = options.dryRun ? '将安装' : '已安装';
    for (const destination of destinations) {
      process.stdout.write(`${action} ${SKILL_NAME} 到 ${destination.platform}：${destination.directory}\n`);
    }
    return 0;
  } catch (error) {
    process.stderr.write(`安装失败：${error.message}\n`);
    return 1;
  }
}

module.exports = {
  RELEASES,
  SKILL_NAME,
  install,
  installAtomically,
  isSafeArchiveEntry,
  latestVersion,
  parseArguments,
  sha256File,
  targetDirectories,
};

if (require.main === module) {
  main().then((code) => { process.exitCode = code; });
}
