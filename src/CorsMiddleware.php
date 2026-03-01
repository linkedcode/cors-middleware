<?php

namespace Linkedcode\Middleware\Cors;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

class CorsMiddleware implements MiddlewareInterface
{
    private array $config;
    private ResponseFactoryInterface $responseFactory;

    public function __construct(ResponseFactoryInterface $responseFactory, array $config = [])
    {
        $this->responseFactory = $responseFactory;
        $this->config = array_merge([
            'allowed_origins'   => ['*'],
            'allowed_methods'   => ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
            'allowed_headers'   => ['Content-Type', 'Authorization', 'X-Requested-With'],
            'exposed_headers'   => [],
            'allow_credentials' => false,
            'max_age'           => 86400,
        ], $config);
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $origin = $request->getHeaderLine('Origin');

        // Preflight request (OPTIONS)
        if ($request->getMethod() === 'OPTIONS') {
            $response = $this->responseFactory->createResponse(204);
            return $this->addCorsHeaders($response, $origin);
        }

        // Request normal
        $response = $handler->handle($request);
        return $this->addCorsHeaders($response, $origin);
    }

    private function addCorsHeaders(ResponseInterface $response, string $origin): ResponseInterface
    {
        $allowedOrigin = $this->resolveOrigin($origin);

        if ($allowedOrigin === null) {
            return $response;
        }

        $response = $response
            ->withHeader('Access-Control-Allow-Origin', $allowedOrigin)
            ->withHeader('Access-Control-Allow-Methods', implode(', ', $this->config['allowed_methods']))
            ->withHeader('Access-Control-Allow-Headers', implode(', ', $this->config['allowed_headers']))
            ->withHeader('Access-Control-Max-Age', (string) $this->config['max_age']);

        // Solo enviar credentials si el origen NO es wildcard
        if ($this->config['allow_credentials'] && $allowedOrigin !== '*') {
            $response = $response->withHeader('Access-Control-Allow-Credentials', 'true');
        }

        if (!empty($this->config['exposed_headers'])) {
            $response = $response->withHeader(
                'Access-Control-Expose-Headers',
                implode(', ', $this->config['exposed_headers'])
            );
        }

        $vary = $response->getHeaderLine('Vary');
        $response = $response->withHeader('Vary', $vary ? $vary . ', Origin' : 'Origin');

        return $response;
    }

    private function resolveOrigin(string $origin): ?string
    {
        if (empty($origin)) {
            return null;
        }

        $allowedOrigins = $this->config['allowed_origins'];

        // Si hay wildcard, siempre retorna '*' sin importar las credenciales
        if (in_array('*', $allowedOrigins, true)) {
            return '*';
        }

        if (in_array($origin, $allowedOrigins, true)) {
            return $origin;
        }

        return null;
    }
}
