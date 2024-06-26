/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.jboss.as.test.integration.ee.injection.resource.persistenceunitref;

import static org.junit.Assert.assertNotNull;

import javax.naming.InitialContext;
import javax.naming.NamingException;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.shrinkwrap.api.Archive;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 *
 * @author Stuart Douglas
 */
@RunWith(Arquillian.class)
public class PersistenceUnitRefTestCase {
    private static final String ARCHIVE_NAME = "persistence-unit-ref";

    private static final String persistence_xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?> " +
            "<persistence xmlns=\"http://java.sun.com/xml/ns/persistence\" version=\"1.0\">" +
            "  <persistence-unit name=\"mypc\">" +
            "    <description>Persistence Unit." +
            "    </description>" +
            "  <jta-data-source>java:jboss/datasources/ExampleDS</jta-data-source>" +
            "  <exclude-unlisted-classes>true</exclude-unlisted-classes>" +
            "  <class>" + PuMyEntity.class.getName() + "</class>" +
            "<properties> <property name=\"hibernate.hbm2ddl.auto\" value=\"create-drop\"/></properties>" +
            "  </persistence-unit>" +
            "  <persistence-unit name=\"otherpc\">" +
            "    <description>Persistence Unit." +
            "    </description>" +
            "  <jta-data-source>java:jboss/datasources/ExampleDS</jta-data-source>" +
            "  <exclude-unlisted-classes>true</exclude-unlisted-classes>" +
            "  <class>" + PuOtherEntity.class.getName() + "</class>" +
            "<properties> <property name=\"hibernate.hbm2ddl.auto\" value=\"create-drop\"/></properties>" +
            "  </persistence-unit>" +
            "</persistence>";


    @Deployment
    public static Archive<?> deploy() {

        WebArchive war = ShrinkWrap.create(WebArchive.class, ARCHIVE_NAME + ".war");
        war.addPackage(PersistenceUnitRefTestCase.class.getPackage());

        war.addAsResource(new StringAsset(persistence_xml), "META-INF/persistence.xml");
        war.addAsWebInfResource(getWebXml(),"web.xml");
        return war;
    }

    @Test
    public void testCorrectPersistenceUnitInjectedFromAnnotation() throws NamingException {
        PuBean bean = getManagedBean();
        bean.getMypu().getMetamodel().entity(PuMyEntity.class);
    }

    @Test
    public void testCorrectPersistenceUnitInjectedFromAnnotation2() throws NamingException {
        try {
            PuBean bean = getManagedBean();
            bean.getMypu().getMetamodel().entity(PuOtherEntity.class);
        } catch (IllegalArgumentException e) {
            //all is fine!
            return;
        }
        Assert.fail("IllegalArgumentException should occur but didn't!");
    }

    @Test
    public void testCorrectPersistenceUnitInjectedFromPersistenceUnitRef() throws NamingException {
        try {
            PuBean bean = getManagedBean();
            bean.getOtherpc().getMetamodel().entity(PuMyEntity.class);
        } catch (IllegalArgumentException e) {
            //all is fine!
            return;
        }
        Assert.fail("IllegalArgumentException should occur but didn't!");
    }

    @Test
    public void testCorrectPersistenceUnitInjectedFromPersistenceUnitRef2() throws NamingException {
        PuBean bean = getManagedBean();
        bean.getOtherpc().getMetamodel().entity(PuOtherEntity.class);
    }

    @Test
    public void testCorrectPersistenceUnitInjectedFromRefInjectionTarget() throws NamingException {
        PuBean bean = getManagedBean();
        bean.getMypu2().getMetamodel().entity(PuMyEntity.class);
    }

    @Test
    public void testCorrectPersistenceUnitInjectedFromRefInjectionTarget2() throws NamingException {
        try {
            PuBean bean = getManagedBean();
            bean.getMypu2().getMetamodel().entity(PuOtherEntity.class);
        } catch (IllegalArgumentException e) {
            //all is fine!
            return;
        }
        Assert.fail("IllegalArgumentException should occur but didn't!");
    }


    private PuBean getManagedBean() throws NamingException {
        InitialContext initialContext = new InitialContext();
        PuBean bean = (PuBean) initialContext.lookup("java:module/puManagedBean");
        assertNotNull(bean);
        return bean;
    }


    private static StringAsset getWebXml() {
        return new StringAsset("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "\n" +
                "<web-app version=\"3.0\"\n" +
                "         xmlns=\"http://java.sun.com/xml/ns/javaee\"\n" +
                "         xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n" +
                "         xsi:schemaLocation=\"http://java.sun.com/xml/ns/javaee http://java.sun.com/xml/ns/javaee/web-app_3_0.xsd\"\n" +
                "         metadata-complete=\"false\">\n" +
                "\n" +
                "    <persistence-unit-ref>\n" +
                "        <persistence-unit-ref-name>otherPcBinding</persistence-unit-ref-name>\n" +
                "        <persistence-unit-name>otherpc</persistence-unit-name>\n" +
                "    </persistence-unit-ref>\n" +                "\n" +
                "    <persistence-unit-ref>\n" +
                "        <persistence-unit-ref-name>AnotherPuBinding</persistence-unit-ref-name>\n" +
                "        <persistence-unit-name>mypc</persistence-unit-name>\n" +
                "        <injection-target>" +
                "           <injection-target-class>"+ PuBean.class.getName()+"</injection-target-class>"+
                "           <injection-target-name>mypu2</injection-target-name>" +
                "        </injection-target>\n" +
                "    </persistence-unit-ref>\n" +
                "\n" +
                "</web-app>");
    }

}
