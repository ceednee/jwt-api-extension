<?php

/*
 * This file is part of the Behat JWT Token.
 * (c) Konstantin Kudryashov <ever.zet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Behat\JwtApiExtension\ServiceContainer;

use Behat\Behat\Context\ServiceContainer\ContextExtension;
use Behat\Testwork\ServiceContainer\Extension as ExtensionInterface;
use Behat\Testwork\ServiceContainer\ExtensionManager;
use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

/**
 * JWT Token extension for Behat.
 *
 * @author Anton Popov <cnam812@gmail.com>
 */
class JwtApiExtension implements ExtensionInterface
{
    const CLIENT_ID = 'web_api.client';

    /**
     * {@inheritdoc}
     */
    public function getConfigKey()
    {
        return 'jwt';
    }

    /**
     * {@inheritdoc}
     */
    public function initialize(ExtensionManager $extensionManager)
    {
    }

    /**
     * {@inheritdoc}
     */
    public function configure(ArrayNodeDefinition $builder)
    {
        $builder
            ->addDefaultsIfNotSet()
            ->children()
                ->scalarNode('base_url')
                    ->defaultValue('localhost')
                ->end()
                ->scalarNode('ttl')
                    ->defaultValue(86400)
                ->end()
                ->scalarNode('secret_key')
                    ->defaultValue('')
                ->end()
                ->scalarNode('header_name')
                    ->defaultValue('Authorization')
                ->end()
                ->scalarNode('token_prefix')
                    ->defaultValue('')
                ->end()
                ->scalarNode('encoded_field_name')
                    ->defaultValue('username')
                ->end()
                ->scalarNode('jwt_private_key_path')
                    ->defaultValue('')
                ->end()
                ->scalarNode('jwt_public_key_path')
                    ->defaultValue('')
                ->end()
                ->scalarNode('jwt_pass_phrase')
                    ->defaultValue('')
                ->end()
             ->end()
        ->end();
    }

    /**
     * {@inheritdoc}
     */
    public function load(ContainerBuilder $container, array $config)
    {
        $this->loadClient($container, $config);
        $this->loadContextInitializer($container, $config);
    }

    private function loadClient(ContainerBuilder $container, $config)
    {
        $definition = new Definition('GuzzleHttp\Client', array($config));
        $container->setDefinition(self::CLIENT_ID, $definition);
    }

    private function loadContextInitializer(ContainerBuilder $container, $config)
    {
        $definition = new Definition('Behat\JwtApiExtension\Context\Initializer\ApiClientAwareInitializer', array(
            new Reference(self::CLIENT_ID),
            $config
        ));
        $definition->addTag(ContextExtension::INITIALIZER_TAG);
        $container->setDefinition('jwt.context_initializer', $definition);
    }

    /**
     * {@inheritdoc}
     */
    public function process(ContainerBuilder $container)
    {
    }
}
