<?php
/**
 * @author qiang.ou<qingqianludao@gmail.com>
 */

namespace Etcd\Tests;

use Etcd\Client;
use PHPUnit\Framework\TestCase;

class ClientTest extends TestCase
{
    protected Client $client;

    protected string $key = '/test';

    protected string $role = 'root';
    protected string $user = 'root';
    protected string $password = '123456';

    protected function setUp(): void
    {
        $this->client = new Client(version: 'v3beta');
        $this->client->setPretty(true);
    }

    public function testPutAndRange(): void
    {
        $value = 'testput';
        $this->client->put($this->key, $value);

        $body = $this->client->get($this->key);
        $this->assertArrayHasKey($this->key, $body);
        $this->assertEquals($value, $body[$this->key]);
    }

    public function testGetAllKeys(): void
    {
        $body = $this->client->getAllKeys();
        $this->assertNotEmpty($body);
    }

    public function testGetKeysWithPrefix(): void
    {
        $body = $this->client->getKeysWithPrefix('/');
        $this->assertNotEmpty($body);
    }

    public function testDeleteRange(): void
    {
        $this->client->del($this->key);
        $body = $this->client->get($this->key);
        $this->assertArrayNotHasKey($this->key, $body);
    }

    public function testGrant(): void
    {
        $body = $this->client->grant(3600);
        $this->assertArrayHasKey('ID', $body);
        $id = (int) $body['ID'];

        $body = $this->client->timeToLive($id);
        $this->assertArrayHasKey('ID', $body);

        $this->client->keepAlive($id);
        $this->assertArrayHasKey('ID', $body);

        $this->client->revoke($id);
    }

    public function testAddRole(): void
    {
        self::assertEquals([], $this->client->addRole($this->role));
    }

    public function testAddUser(): void
    {
        $this->client->addUser($this->user, $this->password);
    }

    public function testChangeUserPassword(): void
    {
        $this->client->changeUserPassword($this->user, '456789');
        $this->client->changeUserPassword($this->user, $this->password);
    }

    public function testGrantUserRole(): void
    {
        $this->client->grantUserRole($this->user, $this->role);
    }

    public function testGetRole(): void
    {
        $this->client->getRole($this->role);
    }

    public function testRoleList()
    {
        $body = $this->client->roleList();
        if (!in_array($this->role, $body)) {
            $this->fail('role not exist');
        }
    }

    public function testGetUser()
    {
        $this->client->getUser($this->user);
    }

    public function testUserList()
    {
        $body = $this->client->userList();
        if (!in_array($this->user, $body)) {
            $this->fail('user not exist');
        }
    }

    public function testGrantRolePermission()
    {
        $this->client->grantRolePermission($this->role,
            Client::PERMISSION_READWRITE, '\0', 'z' );
    }

    public function testAuthenticate()
    {
        $this->client->authEnable();
        $token = $this->client->authenticate($this->user, $this->password);
        $this->client->setToken($token);
        $this->client->addUser('admin', '345678');
        $this->client->addRole('admin');
        $this->client->grantUserRole('admin', 'admin');

        $this->client->authDisable();
        $this->client->deleteRole('admin');
        $this->client->deleteUser('admin');
    }

    public function testRevokeRolePermission()
    {
        $this->client->revokeRolePermission($this->role, '\0', 'z');
    }

    public function testRevokeUserRole()
    {
        $this->client->revokeUserRole($this->user, $this->role);
    }

    public function testDeleteRole()
    {
        $this->client->deleteRole($this->role);
    }

    public function testDeleteUser()
    {
        $this->client->deleteUser($this->user);
    }
}