NAME=gossamer
VERSION=1.2.10
BUILD=43

FULLV := $(VERSION).$(BUILD)

.PHONY: package

package:
        rm -f gossamer-*.tar.gz
        rm -rf gossamer*
        wget https://github.com/GESkunkworks/gossamer/releases/download/$(VERSION)/gossamer-linux-amd64-$(FULLV).tar.gz
        tar -xvzf gossamer-linux-amd64-$(FULLV).tar.gz
        #fpm -s dir -t deb -n $(NAME) -v $(VERSION) --prefix /opt/jenkins jenkins.war
        fpm -s dir -t rpm -n $(NAME) -v $(FULLV) --prefix /usr/bin gossamer
