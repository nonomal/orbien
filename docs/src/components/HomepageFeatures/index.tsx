import type {ReactNode} from 'react';
import clsx from 'clsx';
import Heading from '@theme/Heading';
import Translate from '@docusaurus/Translate';

import styles from './styles.module.css';

type FeatureItem = {
    title: ReactNode;
    description: ReactNode;
};

const FeatureList: FeatureItem[] = [
    {
        title: (
            <Translate id="homepage.feature.perf.title">高性能</Translate>
        ),
        description: (
            <Translate id="homepage.feature.perf.desc">
                高性能、低延迟、抗丢包、内存占用低、无GC停顿，适合长期服务器运行
            </Translate>
        ),
    },
    {
        title: (
            <Translate id="homepage.feature.tunnel.title">多协议隧道</Translate>
        ),
        description: (
            <Translate id="homepage.feature.tunnel.desc">
                支持 TCP、UDP、HTTP、HTTPS、SOCKS5 协议隧道
            </Translate>
        ),
    },
    {
        title: (
            <Translate id="homepage.feature.transport.title">
                多传输协议
            </Translate>
        ),
        description: (
            <Translate id="homepage.feature.transport.desc">
                支持 TCP、QUIC、KCP、WebSocket 多种传输协议；支持 TCP 多路复用
            </Translate>
        ),
    },
    {
        title: (
            <Translate id="homepage.feature.security.title">安全加密</Translate>
        ),
        description: (
            <Translate id="homepage.feature.security.desc">
                支持 Token 鉴权与 TLS /mTLS 加密传输；HTTPS采用透明转发和可选客户端TLS终止
            </Translate>
        ),
    },
    {
        title: (
            <Translate id="homepage.feature.ops.title">可视化运维</Translate>
        ),
        description: (
            <Translate id="homepage.feature.ops.desc">
                内置轻量服务端 Web 管理界面和原生桌面客户端；支持配置热重载和 ACME 证书自动申请
            </Translate>
        ),
    },
    {
        title: (
            <Translate id="homepage.feature.platform.title">跨平台支持</Translate>
        ),
        description: (
            <Translate id="homepage.feature.platform.desc">
                支持 Windows / macOS / Linux / freeBSD 等平台
            </Translate>
        ),
    },
];

function Feature({title, description}: FeatureItem): ReactNode {
    return (
        <div className={clsx('col col--4', styles.featureCol)}>
            <div className={styles.featureCard}>
                <Heading as="h3" className={styles.featureTitle}>
                    {title}
                </Heading>
                <p className={styles.featureDesc}>{description}</p>
            </div>
        </div>
    );
}

export default function HomepageFeatures(): ReactNode {
    return (
        <section className={styles.features}>
            <div className="container">
                <div className="row">
                    {FeatureList.map((item, idx) => (
                        <Feature key={idx} {...item} />
                    ))}
                </div>
            </div>
        </section>
    );
}
