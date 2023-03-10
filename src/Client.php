<?php
/**
 * @see     https://github.com/coreos/etcd/blob/master/etcdserver/etcdserverpb/rpc.proto
 * @author  ouqiang<qingqianludao@gmail.com>
 */

namespace Etcd;

use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Exception\GuzzleException;

class Client
{
    // KV
    public const URI_PUT = 'kv/put';
    public const URI_RANGE = 'kv/range';
    public const URI_DELETE_RANGE = 'kv/deleterange';
    public const URI_TXN = 'kv/txn';
    public const URI_COMPACTION = 'kv/compaction';

    // Lease
    public const URI_GRANT = 'lease/grant';
    public const URI_REVOKE = 'kv/lease/revoke';
    public const URI_KEEPALIVE = 'lease/keepalive';
    public const URI_TIMETOLIVE = 'kv/lease/timetolive';

    // Role
    public const URI_AUTH_ROLE_ADD = 'auth/role/add';
    public const URI_AUTH_ROLE_GET = 'auth/role/get';
    public const URI_AUTH_ROLE_DELETE = 'auth/role/delete';
    public const URI_AUTH_ROLE_LIST = 'auth/role/list';

    // Authenticate
    public const URI_AUTH_ENABLE = 'auth/enable';
    public const URI_AUTH_DISABLE = 'auth/disable';
    public const URI_AUTH_AUTHENTICATE = 'auth/authenticate';

    // User
    public const URI_AUTH_USER_ADD = 'auth/user/add';
    public const URI_AUTH_USER_GET = 'auth/user/get';
    public const URI_AUTH_USER_DELETE = 'auth/user/delete';
    public const URI_AUTH_USER_CHANGE_PASSWORD = 'auth/user/changepw';
    public const URI_AUTH_USER_LIST = 'auth/user/list';

    public const URI_AUTH_ROLE_GRANT = 'auth/role/grant';
    public const URI_AUTH_ROLE_REVOKE = 'auth/role/revoke';

    public const URI_AUTH_USER_GRANT = 'auth/user/grant';
    public const URI_AUTH_USER_REVOKE = 'auth/user/revoke';

    public const PERMISSION_READ = 0;
    public const PERMISSION_WRITE = 1;
    public const PERMISSION_READWRITE = 2;

    public const DEFAULT_HTTP_TIMEOUT = 30;
    /**
     * @var array
     */
    protected array $httpOptions;
    protected bool $pretty = false;
    /**
     * host:port
     */
    protected string $server;
    protected ?string $token = null;
    /**
     * api version
     */
    protected string $version;

    public function __construct($server = '127.0.0.1:2379', $version = 'v3alpha')
    {
        $this->server = rtrim($server, "/");
        if (!str_starts_with($this->server, 'http')) {
            $this->server = 'http://'.$this->server;
        }
        $this->version = trim($version);
    }

    /**
     * add a new role.
     *
     * @return array
     *
     * @throws GuzzleException
     * @throws \JsonException
     */
    public function addRole(string $name): array
    {
        $params = [
            'name' => $name,
        ];

        return $this->request(self::URI_AUTH_ROLE_ADD, $params);
    }

    /**
     * add a new user
     *
     * @return array
     *
     * @throws GuzzleException
     * @throws \JsonException
     */
    public function addUser(string $user, string $password): array
    {
        $params = [
            'name' => $user,
            'password' => $password,
        ];

        return $this->request(self::URI_AUTH_USER_ADD, $params);
    }

    /**
     * disable authentication
     *
     * @return array
     *
     * @throws GuzzleException
     * @throws \JsonException
     */
    public function authDisable(): array
    {
        $body = $this->request(self::URI_AUTH_DISABLE);
        $this->clearToken();

        return $body;
    }

    /**
     * enable authentication
     *
     * @return array
     *
     * @throws GuzzleException
     * @throws \JsonException
     */
    public function authEnable(): array
    {
        $body = $this->request(self::URI_AUTH_ENABLE);
        $this->clearToken();

        return $body;
    }

    // region kv

    /**
     * @return array
     *
     * @throws GuzzleException
     * @throws \JsonException
     */
    public function authenticate(string $user, string $password): array
    {
        $params = [
            'name' => $user,
            'password' => $password,
        ];

        $body = $this->request(self::URI_AUTH_AUTHENTICATE, $params);
        if ($this->pretty && isset($body['token'])) {
            return $body['token'];
        }

        return $body;
    }

    /**
     * change the password of a specified user.
     *
     * @return array
     *
     * @throws GuzzleException
     * @throws \JsonException
     */
    public function changeUserPassword(string $user, string $password): array
    {
        $params = [
            'name' => $user,
            'password' => $password,
        ];

        return $this->request(self::URI_AUTH_USER_CHANGE_PASSWORD, $params);
    }

    public function clearToken(): void
    {
        $this->token = null;
    }

    /**
     * Compact compacts the event history in the etcd key-value store.
     * The key-value\nstore should be periodically compacted
     * or the event history will continue to grow\nindefinitely.
     *
     * @return array
     *
     * @throws GuzzleException
     * @throws \JsonException
     */
    public function compaction(int $revision, bool $physical = false): array
    {
        $params = [
            'revision' => $revision,
            'physical' => $physical,
        ];

        return $this->request(self::URI_COMPACTION, $params);
    }

    /**
     * Removes the specified key or range of keys
     *
     * @param array  $options
     *        string range_end
     *        bool   prev_kv
     * @return array
     *
     * @throws GuzzleException
     * @throws \JsonException
     */
    public function del(string $key, array $options = []): array
    {
        $params = [
            'key' => $key,
        ];
        $params = $this->encode($params);
        $options = $this->encode($options);
        $body = $this->request(self::URI_DELETE_RANGE, $params, $options);
        $body = $this->decodeBodyForFields(
            $body,
            'prev_kvs',
            ['key', 'value',]
        );

        if (isset($body['prev_kvs']) && $this->pretty) {
            return $this->convertFields($body['prev_kvs']);
        }

        return $body;
    }

    /**
     * delete a specified role.
     *
     * @return array
     *
     * @throws GuzzleException
     * @throws \JsonException
     */
    public function deleteRole(string $role): array
    {
        $params = [
            'role' => $role,
        ];

        return $this->request(self::URI_AUTH_ROLE_DELETE, $params);
    }

    // endregion kv

    // region lease

    /**
     * delete a specified user
     *
     * @return array
     *
     * @throws GuzzleException
     * @throws \JsonException
     */
    public function deleteUser(string $user): array
    {
        $params = [
            'name' => $user,
        ];

        return $this->request(self::URI_AUTH_USER_DELETE, $params);
    }

    /**
     * Gets the key or a range of keys
     *
     * @param array  $options
     *         string range_end
     *         int    limit
     *         int    revision
     *         int    sort_order
     *         int    sort_target
     *         bool   serializable
     *         bool   keys_only
     *         bool   count_only
     *         int64  min_mod_revision
     *         int64  max_mod_revision
     *         int64  min_create_revision
     *         int64  max_create_revision
     * @return array
     *
     * @throws GuzzleException
     * @throws \JsonException
     */
    public function get(string $key, array $options = []): array
    {
        $params = [
            'key' => $key,
        ];
        $params = $this->encode($params);
        $options = $this->encode($options);
        $body = $this->request(self::URI_RANGE, $params, $options);
        $body = $this->decodeBodyForFields(
            $body,
            'kvs',
            ['key', 'value',]
        );

        if (isset($body['kvs']) && $this->pretty) {
            return $this->convertFields($body['kvs']);
        }

        return $body;
    }

    /**
     * get all keys
     *
     * @return array
     *
     * @throws GuzzleException
     * @throws \JsonException
     */
    public function getAllKeys(): array
    {
        return $this->get("\0", ['range_end' => "\0"]);
    }

    /**
     * get all keys with prefix
     *
     * @return array
     *
     * @throws GuzzleException
     * @throws \JsonException
     */
    public function getKeysWithPrefix(string $prefix): array
    {
        $prefix = trim($prefix);
        if (!$prefix) {
            return [];
        }
        $lastIndex = strlen($prefix) - 1;
        $lastChar = $prefix[$lastIndex];
        $nextAsciiCode = ord($lastChar) + 1;
        $rangeEnd = $prefix;
        $rangeEnd[$lastIndex] = chr($nextAsciiCode);

        return $this->get($prefix, ['range_end' => $rangeEnd]);
    }

    // endregion lease

    // region auth

    /**
     * get detailed role information.
     *
     * @return array
     *
     * @throws GuzzleException
     * @throws \JsonException
     */
    public function getRole(string $role): array
    {
        $params = [
            'role' => $role,
        ];

        $body = $this->request(self::URI_AUTH_ROLE_GET, $params);
        $body = $this->decodeBodyForFields(
            $body,
            'perm',
            ['key', 'range_end',]
        );
        if ($this->pretty && isset($body['perm'])) {
            return $body['perm'];
        }

        return $body;
    }

    /**
     * get detailed user information
     *
     * @return array
     *
     * @throws GuzzleException
     * @throws \JsonException
     */
    public function getUser(string $user): array
    {
        $params = [
            'name' => $user,
        ];

        $body = $this->request(self::URI_AUTH_USER_GET, $params);
        if ($this->pretty && isset($body['roles'])) {
            return $body['roles'];
        }

        return $body;
    }

    /**
     * LeaseGrant creates a lease which expires if the server does not receive a
     * keepAlive\nwithin a given time to live period. All keys attached to the lease
     * will be expired and\ndeleted if the lease expires.
     * Each expired key generates a delete event in the event history.
     *
     * @param int $ttl    TTL is the advisory time-to-live in seconds.
     * @param int $id     ID is the requested ID for the lease.
     *                    If ID is set to 0, the lessor chooses an ID.
     * @return array
     *
     * @throws GuzzleException
     * @throws \JsonException
     */
    public function grant(int $ttl, int $id = 0): array
    {
        $params = [
            'TTL' => $ttl,
            'ID' => $id,
        ];

        return $this->request(self::URI_GRANT, $params);
    }

    /**
     * grant a permission of a specified key or range to a specified role.
     *
     * @return array
     *
     * @throws GuzzleException
     * @throws \JsonException
     */
    public function grantRolePermission(string $role, int $permType, string $key, string $rangeEnd = null): array
    {
        $params = [
            'name' => $role,
            'perm' => [
                'permType' => $permType,
                'key' => base64_encode($key),
            ],
        ];
        if ($rangeEnd !== null) {
            $params['perm']['range_end'] = base64_encode($rangeEnd);
        }

        return $this->request(self::URI_AUTH_ROLE_GRANT, $params);
    }

    /**
     * grant a role to a specified user.
     *
     * @return array
     *
     * @throws GuzzleException
     * @throws \JsonException
     */
    public function grantUserRole(string $user, string $role): array
    {
        $params = [
            'user' => $user,
            'role' => $role,
        ];

        return $this->request(self::URI_AUTH_USER_GRANT, $params);
    }

    /**
     * keeps the lease alive by streaming keep alive requests
     * from the client\nto the server and streaming keep alive responses
     * from the server to the client.
     *
     * @param int $id ID is the lease ID for the lease to keep alive.
     * @return array
     *
     * @throws GuzzleException
     * @throws \JsonException
     */
    public function keepAlive(int $id): array
    {
        $params = [
            'ID' => $id,
        ];

        $body = $this->request(self::URI_KEEPALIVE, $params);

        if (!isset($body['result'])) {
            return $body;
        }

        // response "result" field, etcd bug?
        return [
            'ID' => $body['result']['ID'],
            'TTL' => $body['result']['TTL'],
        ];
    }

    /**
     * Put puts the given key into the key-value store.
     * A put request increments the revision of the key-value
     * store\nand generates one event in the event history.
     *
     * @param array  $options
     *                        int64  lease
     *                        bool   prev_kv
     *                        bool   ignore_value
     *                        bool   ignore_lease
     * @return array
     *
     * @throws GuzzleException
     * @throws \JsonException
     */
    public function put(string $key, string $value, array $options = []): array
    {
        $params = [
            'key' => $key,
            'value' => $value,
        ];

        $params = $this->encode($params);
        $options = $this->encode($options);
        $body = $this->request(self::URI_PUT, $params, $options);
        $body = $this->decodeBodyForFields(
            $body,
            'prev_kv',
            ['key', 'value',]
        );

        if (isset($body['prev_kv']) && $this->pretty) {
            return $this->convertFields($body['prev_kv']);
        }

        return $body;
    }

    /**
     * revokes a lease. All keys attached to the lease will expire and be deleted.
     *
     * @param int $id ID is the lease ID to revoke. When the ID is revoked,
     *                all associated keys will be deleted.
     * @return array
     *
     * @throws GuzzleException
     * @throws \JsonException
     */
    public function revoke(int $id): array
    {
        $params = [
            'ID' => $id,
        ];

        return $this->request(self::URI_REVOKE, $params);
    }

    /**
     * revoke a key or range permission of a specified role.
     *
     * @return array
     *
     * @throws GuzzleException
     * @throws \JsonException
     */
    public function revokeRolePermission(string $role, string $key, string $rangeEnd = null): array
    {
        $params = [
            'role' => $role,
            'key' => $key,
        ];
        if ($rangeEnd !== null) {
            $params['range_end'] = $rangeEnd;
        }

        return $this->request(self::URI_AUTH_ROLE_REVOKE, $params);
    }

    /**
     * revoke a role of specified user.
     *
     * @return array
     *
     * @throws GuzzleException
     * @throws \JsonException
     */
    public function revokeUserRole(string $user, string $role): array
    {
        $params = [
            'name' => $user,
            'role' => $role,
        ];

        return $this->request(self::URI_AUTH_USER_REVOKE, $params);
    }

    /**
     * get lists of all roles
     *
     * @return array
     *
     * @throws GuzzleException
     * @throws \JsonException
     */
    public function roleList(): array
    {
        $body = $this->request(self::URI_AUTH_ROLE_LIST);

        if ($this->pretty && isset($body['roles'])) {
            return $body['roles'];
        }

        return $body;
    }

    public function setHttpOptions(array $options): void
    {
        $this->httpOptions = $options;
    }

    public function setPretty($enabled): void
    {
        $this->pretty = $enabled;
    }

    public function setToken($token): void
    {
        $this->token = $token;
    }

    /**
     * retrieves lease information.
     *
     * @param int  $id ID is the lease ID for the lease.
     * @return array
     *
     * @throws GuzzleException
     * @throws \JsonException
     */
    public function timeToLive(int $id, bool $keys = false): array
    {
        $params = [
            'ID' => $id,
            'keys' => $keys,
        ];

        $body = $this->request(self::URI_TIMETOLIVE, $params);

        if (isset($body['keys'])) {
            $body['keys'] = array_map(static function ($value): false|string {
                return base64_decode($value);
            }, $body['keys']);
        }

        return $body;
    }

    /**
     * get a list of all users.
     *
     * @return array
     *
     * @throws GuzzleException
     * @throws \JsonException
     */
    public function userList(): array
    {
        $body = $this->request(self::URI_AUTH_USER_LIST);
        if ($this->pretty && isset($body['users'])) {
            return $body['users'];
        }

        return $body;
    }

    // endregion auth

    protected function convertFields(array $data)
    {
        if (!isset($data[0])) {
            return $data['value'];
        }

        $map = [];
        foreach ($data as $value) {
            $map[$value['key']] = $value['value'];
        }

        return $map;
    }

    /**
     * @param array  $body
     * @param array  $fields
     *
     * @return array
     */
    protected function decodeBodyForFields(array $body, string $bodyKey, array $fields): array
    {
        if (!isset($body[$bodyKey])) {
            return $body;
        }
        $data = $body[$bodyKey];
        if (!isset($data[0])) {
            $data = [$data];
        }
        foreach ($data as $key => $value) {
            foreach ($fields as $field) {
                if (isset($value[$field])) {
                    $data[$key][$field] = base64_decode($value[$field]);
                }
            }
        }

        if (isset($body[$bodyKey][0])) {
            $body[$bodyKey] = $data;
        } else {
            $body[$bodyKey] = $data[0];
        }

        return $body;
    }

    /**
     * @param array $data
     *
     * @return array
     */
    protected function encode(array $data): array
    {

        foreach ($data as $key => $value) {
            if (is_string($value)) {
                $data[$key] = base64_encode($value);
            }
        }

        return $data;
    }

    protected function getHttpClient(): ?HttpClient
    {
        static $httpClient = null;

        if ($httpClient !== null) {
            return $httpClient;
        }

        $baseUri = sprintf('%s/%s/', $this->server, $this->version);
        $this->httpOptions['base_uri'] = $baseUri;

        if (!array_key_exists('timeout', $this->httpOptions)) {
            $this->httpOptions['timeout'] = self::DEFAULT_HTTP_TIMEOUT;
        }

        return new HttpClient($this->httpOptions);
    }

    /**
     * @param array $params
     * @param array $options
     *
     * @return array
     *
     * @throws GuzzleException
     * @throws \JsonException
     */
    protected function request(string $uri, array $params = [], array $options = []): array
    {
        if ($options) {
            $params = array_merge($params, $options);
        }

        if (!$params) {
            $params['php-etcd-client'] = 1;
        }
        $data = [
            'json' => $params,
        ];
        if ($this->token) {
            $data['headers'] = ['Grpc-Metadata-Token' => $this->token];
        }

        $response = $this->getHttpClient()?->request('post', $uri, $data);
        $content = $response->getBody()
            ->getContents();

        $body = \json_decode($content, true, 512, \JSON_THROW_ON_ERROR);

        if ($this->pretty && isset($body['header'])) {
            unset($body['header']);
        }

        return $body;
    }
}