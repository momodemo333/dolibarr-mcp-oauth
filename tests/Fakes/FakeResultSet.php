<?php
declare(strict_types=1);
namespace DolibarrMcpOAuth\Tests\Fakes;

/**
 * Cursor over an in-memory row set, mimicking the subset of a Dolibarr
 * DB result resource used by OAuthServer (num_rows + fetch_object).
 */
final class FakeResultSet
{
    /** @var array<int, array<string, mixed>> */
    private array $rows;
    private int $pos = 0;

    /**
     * @param array<int, array<string, mixed>> $rows
     */
    public function __construct(array $rows)
    {
        $this->rows = array_values($rows);
    }

    public function count(): int
    {
        return count($this->rows);
    }

    public function fetch(): ?object
    {
        if (!isset($this->rows[$this->pos])) {
            return null;
        }
        return (object) $this->rows[$this->pos++];
    }
}
