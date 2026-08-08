'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const installer = require('../bin/houyuxi-skills.cjs');

test('解析默认安装命令', () => {
  assert.deepEqual(installer.parseArguments(['add', installer.SKILL_NAME]), {
    target: 'both', version: '1.1.0', force: false, dryRun: false,
  });
});

test('解析目标、版本和替换参数', () => {
  assert.deepEqual(installer.parseArguments([
    'add', installer.SKILL_NAME, '--target', 'claude', '--version', '1.1.0', '--force', '--dry-run',
  ]), { target: 'claude', version: '1.1.0', force: true, dryRun: true });
});

test('拒绝未知 Skill 和不受支持版本', () => {
  assert.throws(() => installer.parseArguments(['add', 'unknown-skill']), /仅支持/);
  assert.throws(() => installer.parseArguments(['add', installer.SKILL_NAME, '--version', '9.9.9']), /不支持的版本/);
});

test('按平台解析安装目录', () => {
  const home = '/tmp/test-home';
  assert.deepEqual(installer.targetDirectories('both', home), [
    { platform: 'Codex', directory: '/tmp/test-home/.codex/skills/avoiding-macos-junk-files' },
    { platform: 'Claude Code', directory: '/tmp/test-home/.claude/skills/avoiding-macos-junk-files' },
  ]);
});

test('拒绝 Zip Slip 条目', () => {
  assert.equal(installer.isSafeArchiveEntry('SKILL.md'), true);
  assert.equal(installer.isSafeArchiveEntry('../SKILL.md'), false);
  assert.equal(installer.isSafeArchiveEntry('/SKILL.md'), false);
});

test('计算文件 SHA-256', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'houyuxi-skills-test-'));
  try {
    const file = path.join(directory, 'payload');
    fs.writeFileSync(file, 'verified payload');
    assert.equal(installer.sha256File(file), crypto.createHash('sha256').update('verified payload').digest('hex'));
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('dry-run 不访问网络或修改已有安装目录', async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'houyuxi-skills-test-'));
  try {
    const existing = path.join(home, '.codex', 'skills', installer.SKILL_NAME);
    fs.mkdirSync(existing, { recursive: true });
    fs.writeFileSync(path.join(existing, 'sentinel'), 'unchanged');
    const targets = await installer.install({ target: 'codex', version: '1.1.0', force: false, dryRun: true }, home);
    assert.equal(targets[0].directory, existing);
    assert.equal(fs.readFileSync(path.join(existing, 'sentinel'), 'utf8'), 'unchanged');
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('原子替换仅在显式 force 时覆盖现有目录', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'houyuxi-skills-test-'));
  try {
    const staged = path.join(root, 'staged');
    const destination = path.join(root, 'home', '.codex', 'skills', installer.SKILL_NAME);
    fs.mkdirSync(staged, { recursive: true });
    fs.mkdirSync(destination, { recursive: true });
    fs.writeFileSync(path.join(staged, 'SKILL.md'), 'new');
    fs.writeFileSync(path.join(destination, 'SKILL.md'), 'old');
    assert.throws(() => installer.installAtomically(staged, [{ directory: destination }], false), /已存在/);
    installer.installAtomically(staged, [{ directory: destination }], true);
    assert.equal(fs.readFileSync(path.join(destination, 'SKILL.md'), 'utf8'), 'new');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
