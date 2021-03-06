import test, { ExecutionContext } from 'ava';
import { buildFastify } from '../utils';
import { userRoute } from '../../src/routes/user';
import { unixTime } from '../../src/libraries';
import { initBasicContext } from '../utils';
import { FastifyInstance } from 'fastify';

initBasicContext(test);

const buildUser = () => {
  return {
    name: 'router',
    dob: unixTime(),
    address: 'router-address',
    description: 'router-description',
    email: 'router-email@gmail.com',
    password: 'router-password',
  };
};

const createUser = async (t: ExecutionContext) => {
  const fastify = await buildFastify(t, userRoute);
  const user = buildUser();
  const response = await fastify.inject({
    method: 'POST',
    url: '/users',
    payload: user,
  });
  return { fastify, user, response };
};

test('POST /users should create', async (t) => {
  const { response } = await createUser(t);
  t.deepEqual(response.statusCode, 201);
});

const requestUserToken = (fastify: FastifyInstance, user: any) => {
  return fastify.inject({
    method: 'POST',
    url: '/user-tokens',
    payload: {
      email: user.email,
      password: user.password,
    },
  });
};

const buildUserRequestMeta = async (fastify: FastifyInstance, user: any) => {
  const response = await requestUserToken(fastify, user);
  const { userId, token } = response.json().data;
  const headers = {
    authorization: `Bearer ${token}`,
  };
  return { userId, token, headers };
};

test('POST /user-tokens should create', async (t) => {
  const { fastify, user } = await createUser(t);
  const response = await requestUserToken(fastify, user);
  t.deepEqual(response.statusCode, 201);
});

test('GET /users should get with token', async (t) => {
  const { fastify, user } = await createUser(t);
  const { headers } = await buildUserRequestMeta(fastify, user);
  const response = await fastify.inject({
    method: 'GET',
    url: `/users`,
    headers,
  });
  t.deepEqual(response.statusCode, 200);
});

test('GET /users should reject without token', async (t) => {
  const fastify = await buildFastify(t, userRoute);
  const response = await fastify.inject({
    method: 'GET',
    url: '/users',
  });
  t.deepEqual(response.statusCode, 401);
});

test('GET /users/:id should get with token', async (t) => {
  const { fastify, user } = await createUser(t);
  const { userId, headers } = await buildUserRequestMeta(fastify, user);
  const response = await fastify.inject({
    method: 'GET',
    url: `/users/${userId}`,
    headers,
  });
  t.deepEqual(response.statusCode, 200);
});

test('GET /users/:id should reject without token', async (t) => {
  const fastify = await buildFastify(t, userRoute);
  const response = await fastify.inject({
    method: 'GET',
    url: '/users/1',
  });
  t.deepEqual(response.statusCode, 401);
});

test('GET /users/:id should reject if :id does not match token', async (t) => {
  const { fastify, user } = await createUser(t);
  const { userId, headers } = await buildUserRequestMeta(fastify, user);
  const response = await fastify.inject({
    method: 'GET',
    url: `/users/${userId + 1}`,
    headers,
  });
  t.deepEqual(response.statusCode, 403);
});

test('PUT /users/:id with password should invalidate existing tokens', async (t) => {
  const { fastify, user } = await createUser(t);
  const { userId, headers } = await buildUserRequestMeta(fastify, user);

  // update password
  {
    const response = await fastify.inject({
      method: 'PUT',
      url: `/users/${userId}`,
      headers,
      payload: {
        password: user.password,
      },
    });
    t.deepEqual(response.statusCode, 200);
  }

  // should success with new token
  {
    const { headers: newHeaders } = await buildUserRequestMeta(fastify, user);
    const response = await fastify.inject({
      method: 'GET',
      url: `/users/${userId}`,
      headers: newHeaders,
    });
    t.deepEqual(response.statusCode, 200);
  }

  // should fail with old token
  {
    const response = await fastify.inject({
      method: 'GET',
      url: `/users/${userId}`,
      headers,
    });
    t.deepEqual(response.statusCode, 401);
  }
});
