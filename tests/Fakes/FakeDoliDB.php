<?php
declare(strict_types=1);
namespace DolibarrMcpOAuth\Tests\Fakes;

/**
 * In-memory fake of the subset of Dolibarr's DoliDB API used by
 * OAuthServer: query/escape/idate/num_rows/fetch_object/lasterror.
 *
 * It "executes" the exact SQL shapes OAuthServer generates (simple
 * single-table INSERT/SELECT/UPDATE/DELETE with an "AND"-only WHERE
 * clause) against an in-memory array store. It is not a SQL engine —
 * only what OAuthServer actually emits is supported.
 */
final class FakeDoliDB
{
    /** @var array<string, array<int, array<string, mixed>>> */
    private array $tables = [];

    /** @var array<string, int> */
    private array $autoIncrement = [];

    /** @var array<string, array{login: string, status: int}> api_key (clear) => user row, for the aliased OR-based llx_user lookup used by HttpEndpoint */
    private array $seededApiKeys = [];

    private string $lastError = '';
    private string $lastTable = '';

    /**
     * Make the "SELECT ... FROM ...user as u WHERE u.api_key = '...' OR
     * u.api_key = '...'" lookup (HttpEndpoint's llx_user validation, mirroring
     * the native REST API) succeed for this clear-text key.
     */
    public function seedUserApiKey(string $key, string $login = 'testuser', int $status = 1): void
    {
        $this->seededApiKeys[$key] = ['login' => $login, 'status' => $status];
    }

    public function escape($value): string
    {
        return addslashes((string) $value);
    }

    public function idate($timestamp): string
    {
        return (string) $timestamp;
    }

    /**
     * @return FakeResultSet|bool
     */
    public function query(string $sql)
    {
        $sql = trim($sql);

        if (preg_match('/^INSERT INTO\s+(\S+)\s*\(([^)]*)\)\s*VALUES\s*\((.*)\)$/is', $sql, $m)) {
            return $this->handleInsert($m[1], $m[2], $m[3]);
        }
        // Aliased OR-based lookup ("... as u WHERE u.api_key = 'x' OR u.api_key = 'y'"),
        // as issued by HttpEndpoint::resolveApiKey(). Not a generic SQL engine:
        // this one shape is special-cased since the generic handlers below only
        // understand AND-only WHERE clauses without table aliases.
        if (preg_match('/^SELECT\s+u\.rowid.*?\s+FROM\s+\S+\s+as\s+u\s+WHERE\s+u\.api_key\s*=\s*\'((?:[^\'\\\\]|\\\\.)*)\'\s+OR\s+u\.api_key\s*=\s*\'(?:[^\'\\\\]|\\\\.)*\'\s*$/is', $sql, $m)) {
            return $this->handleUserApiKeySelect($m[1]);
        }
        if (preg_match('/^SELECT\s+.*?\s+FROM\s+(\S+)(?:\s+WHERE\s+(.*))?$/is', $sql, $m)) {
            return $this->handleSelect($m[1], $m[2] ?? '');
        }
        if (preg_match('/^UPDATE\s+(\S+)\s+SET\s+(.*?)\s+WHERE\s+(.*)$/is', $sql, $m)) {
            return $this->handleUpdate($m[1], $m[2], $m[3]);
        }
        if (preg_match('/^DELETE FROM\s+(\S+)(?:\s+WHERE\s+(.*))?$/is', $sql, $m)) {
            return $this->handleDelete($m[1], $m[2] ?? '');
        }

        $this->lastError = 'FakeDoliDB: unsupported query: '.$sql;
        return false;
    }

    /**
     * @param FakeResultSet|mixed $resql
     */
    public function num_rows($resql): int
    {
        return $resql instanceof FakeResultSet ? $resql->count() : 0;
    }

    /**
     * @param FakeResultSet|mixed $resql
     */
    public function fetch_object($resql): ?object
    {
        return $resql instanceof FakeResultSet ? $resql->fetch() : null;
    }

    public function lasterror(): string
    {
        return $this->lastError;
    }

    /** Test helper: table name targeted by the last successful INSERT. */
    public function lastInsertTable(): string
    {
        return $this->lastTable;
    }

    // --- internals ------------------------------------------------------

    private function handleInsert(string $table, string $colsRaw, string $valsRaw): bool
    {
        $table = trim($table);
        $cols = array_map('trim', explode(',', $colsRaw));
        $valueTokens = $this->splitTopLevel($valsRaw);

        $row = [];
        foreach ($cols as $i => $col) {
            $row[$col] = $this->parseValue($valueTokens[$i] ?? 'NULL');
        }

        $this->autoIncrement[$table] = ($this->autoIncrement[$table] ?? 0) + 1;
        $row['rowid'] = $this->autoIncrement[$table];

        $this->tables[$table][] = $row;
        $this->lastTable = $table;

        return true;
    }

    private function handleUserApiKeySelect(string $rawEscapedKey): FakeResultSet
    {
        $key = stripslashes($rawEscapedKey);

        if (!isset($this->seededApiKeys[$key])) {
            return new FakeResultSet([]);
        }

        $seed = $this->seededApiKeys[$key];
        return new FakeResultSet([
            ['rowid' => 1, 'login' => $seed['login'], 'status' => $seed['status']],
        ]);
    }

    private function handleSelect(string $table, string $where): FakeResultSet
    {
        $table = trim($table);
        $conditions = $this->parseConditions($where);

        $matched = [];
        foreach ($this->tables[$table] ?? [] as $row) {
            if ($this->rowMatches($row, $conditions)) {
                $matched[] = $row;
            }
        }

        return new FakeResultSet($matched);
    }

    private function handleUpdate(string $table, string $setClause, string $where): bool
    {
        $table = trim($table);
        $conditions = $this->parseConditions($where);

        $assignments = [];
        foreach ($this->splitTopLevel($setClause) as $assignment) {
            if (preg_match('/^(\w+)\s*=\s*(.+)$/s', trim($assignment), $m)) {
                $assignments[$m[1]] = $this->parseValue(trim($m[2]));
            }
        }

        $this->lastAffected = 0;
        if (!isset($this->tables[$table])) {
            return true;
        }

        foreach ($this->tables[$table] as &$row) {
            if ($this->rowMatches($row, $conditions)) {
                foreach ($assignments as $col => $val) {
                    $row[$col] = $val;
                }
                $this->lastAffected++;
            }
        }
        unset($row);

        return true;
    }

    /** Rows touched by the last UPDATE, as DoliDB::affected_rows() reports. */
    private int $lastAffected = 0;

    public function affected_rows($resql): int
    {
        return $this->lastAffected;
    }

    private function handleDelete(string $table, string $where): bool
    {
        $table = trim($table);
        $conditions = $this->parseConditions($where);

        if (!isset($this->tables[$table])) {
            return true;
        }

        $this->tables[$table] = array_values(array_filter(
            $this->tables[$table],
            fn (array $row) => !$this->rowMatches($row, $conditions)
        ));

        return true;
    }

    /**
     * @return array<int, array{0: string, 1: string, 2: mixed}> list of [col, op, value]
     */
    private function parseConditions(string $where): array
    {
        $where = trim($where);
        if ($where === '') {
            return [];
        }

        $conditions = [];
        foreach (preg_split('/\s+AND\s+/i', $where) as $part) {
            if (preg_match('/^(\w+)\s*(>=|<=|=|>|<)\s*(.+)$/s', trim($part), $m)) {
                $conditions[] = [$m[1], $m[2], $this->parseValue(trim($m[3]))];
            }
        }
        return $conditions;
    }

    /**
     * @param array<string, mixed>                     $row
     * @param array<int, array{0: string, 1: string, 2: mixed}> $conditions
     */
    private function rowMatches(array $row, array $conditions): bool
    {
        foreach ($conditions as [$col, $op, $val]) {
            $rowVal = $row[$col] ?? null;
            switch ($op) {
                case '=':
                    if ($rowVal != $val) {
                        return false;
                    }
                    break;
                case '>':
                    if (!($rowVal > $val)) {
                        return false;
                    }
                    break;
                case '<':
                    if (!($rowVal < $val)) {
                        return false;
                    }
                    break;
                case '>=':
                    if (!($rowVal >= $val)) {
                        return false;
                    }
                    break;
                case '<=':
                    if (!($rowVal <= $val)) {
                        return false;
                    }
                    break;
            }
        }
        return true;
    }

    /**
     * Split a comma-separated list at depth 0, respecting single-quoted
     * string literals (produced by our own escape()/quoting), so commas
     * inside quoted values (e.g. JSON) don't break the split.
     *
     * @return array<int, string>
     */
    private function splitTopLevel(string $s): array
    {
        $parts = [];
        $depth = 0;
        $inQuote = false;
        $current = '';
        $len = strlen($s);

        for ($i = 0; $i < $len; $i++) {
            $ch = $s[$i];
            if ($ch === "'") {
                $inQuote = !$inQuote;
                $current .= $ch;
                continue;
            }
            if (!$inQuote) {
                if ($ch === '(') {
                    $depth++;
                }
                if ($ch === ')') {
                    $depth--;
                }
                if ($ch === ',' && $depth === 0) {
                    $parts[] = trim($current);
                    $current = '';
                    continue;
                }
            }
            $current .= $ch;
        }
        if (trim($current) !== '') {
            $parts[] = trim($current);
        }

        return $parts;
    }

    /**
     * @return string|int|float|null
     */
    private function parseValue(string $token)
    {
        $token = trim($token);
        if ($token === '' || strtoupper($token) === 'NULL') {
            return null;
        }
        if (strlen($token) >= 2 && $token[0] === "'" && $token[strlen($token) - 1] === "'") {
            return stripslashes(substr($token, 1, -1));
        }
        if (is_numeric($token)) {
            return strpos($token, '.') !== false ? (float) $token : (int) $token;
        }
        return $token;
    }
}
