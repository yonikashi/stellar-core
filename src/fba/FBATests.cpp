// Copyright 2014 Stellar Development Foundation and contributors. Licensed
// under the ISC License. See the COPYING file at the top-level directory of
// this distribution or at http://opensource.org/licenses/ISC

#include "lib/catch.hpp"
#include "generated/StellarXDR.h"
#include "fba/Ballot.h"
#include "main/test.h"
#include "main/Application.h"
#include "crypto/SHA.h"

using namespace stellar;

// addStatement when we already have it
// checkRatState?
//   we need an application
TEST_CASE("node tests", "[fba]")
{

    SECTION("simple")
    {
        uint256 nodeID;
        Node testNode(nodeID);

        FBAEnvelope sxdr1;
        sxdr1.nodeID = nodeID;
        sxdr1.contents.body.type(FBAStatementType::PREPARE);
        sxdr1.contents.slotBallot.ballot.baseFee = 5;
        StatementPtr s1 = std::make_shared<Statement>(sxdr1);

        REQUIRE(!testNode.hasStatement(s1));
        REQUIRE(!testNode.getHighestStatement(
            FBAStatementType::PREPARE));
        REQUIRE(!testNode.getHighestStatement(
            FBAStatementType::PREPARED));
        REQUIRE(!testNode.getHighestStatement(
            FBAStatementType::COMMIT));
        REQUIRE(!testNode.getHighestStatement(
            FBAStatementType::COMMITTED));

        REQUIRE(testNode.addStatement(s1));
        REQUIRE(testNode.hasStatement(s1));

        REQUIRE(testNode.getHighestStatement(
            FBAStatementType::PREPARE) == s1);
        REQUIRE(!testNode.getHighestStatement(
            FBAStatementType::PREPARED));
        REQUIRE(!testNode.getHighestStatement(
            FBAStatementType::COMMIT));
        REQUIRE(!testNode.getHighestStatement(
            FBAStatementType::COMMITTED));

        sxdr1.contents.slotBallot.ballot.baseFee = 10;
        StatementPtr s2 = std::make_shared<Statement>(sxdr1);
        REQUIRE(testNode.addStatement(s2));
        REQUIRE(testNode.hasStatement(s1));
        REQUIRE(testNode.hasStatement(s2));
        REQUIRE(testNode.getHighestStatement(
            FBAStatementType::PREPARE) == s2);
        REQUIRE(!testNode.getHighestStatement(
            FBAStatementType::PREPARED));
        REQUIRE(!testNode.getHighestStatement(
            FBAStatementType::COMMIT));
        REQUIRE(!testNode.getHighestStatement(
            FBAStatementType::COMMITTED));

        sxdr1.contents.slotBallot.ballot.baseFee = 7;
        StatementPtr s3 = std::make_shared<Statement>(sxdr1);
        REQUIRE(testNode.addStatement(s3));
        REQUIRE(testNode.hasStatement(s1));
        REQUIRE(testNode.hasStatement(s2));
        REQUIRE(testNode.hasStatement(s3));
        REQUIRE(testNode.getHighestStatement(
            FBAStatementType::PREPARE) == s2);
        REQUIRE(!testNode.getHighestStatement(
            FBAStatementType::PREPARED));
        REQUIRE(!testNode.getHighestStatement(
            FBAStatementType::COMMIT));
        REQUIRE(!testNode.getHighestStatement(
            FBAStatementType::COMMITTED));

        sxdr1.contents.body.type(FBAStatementType::PREPARED);
        StatementPtr s4 = std::make_shared<Statement>(sxdr1);
        REQUIRE(testNode.addStatement(s4));
        REQUIRE(testNode.hasStatement(s1));
        REQUIRE(testNode.hasStatement(s2));
        REQUIRE(testNode.hasStatement(s3));
        REQUIRE(testNode.hasStatement(s4));
        REQUIRE(testNode.getHighestStatement(
            FBAStatementType::PREPARE) == s2);
        REQUIRE(testNode.getHighestStatement(
            FBAStatementType::PREPARED) == s4);
        REQUIRE(!testNode.getHighestStatement(
            FBAStatementType::COMMIT));
        REQUIRE(!testNode.getHighestStatement(
            FBAStatementType::COMMITTED));
    }

    SECTION("checkRatState")
    {
    }
}

TEST_CASE("end to end", "[fba]")
{
    SECTION("first")
    {
        Config cfg;
        cfg.QUORUM_THRESHOLD = 3;
        cfg.HTTP_PORT = 0;
        cfg.START_NEW_NETWORK = true;
        cfg.VALIDATION_SEED = sha512_256("seed");

        uint256 nodeID[5];

        for(int n = 0; n < 5; n++)
        {
            nodeID[n] = sha512_256("hello");
            nodeID[n][0] = n;
            cfg.QUORUM_SET.push_back(nodeID[n]);
        }

        VirtualClock clock;
        Application app(clock, cfg);


        Node testNode(nodeID[0]);
        BallotPtr ballot = std::make_shared<Ballot>();

        REQUIRE(Node::NOTPLEDGING_STATE ==
                testNode.checkRatState(FBAStatementType::PREPARE,
                                       ballot, 1, 1, app));

        SlotBallot slotBallot;
        slotBallot.ballot = *ballot.get();
        slotBallot.ledgerIndex = 1;
        //slotBallot.previousLedgerHash;

        for(int n = 0; n < 5; n++)
        {
            StatementPtr statement=std::make_shared<Statement>(FBAStatementType::PREPARE,
                nodeID[n], app.getFBAGateway().getOurQuorumSet()->getHash(), 
                slotBallot);
            app.getFBAGateway().recvStatement(statement);
        }



    }
}

TEST_CASE("ballot tests", "[fba]")
{

    Ballot b1;

    b1.baseFee = 10;
    b1.closeTime = 10;
    b1.index = 1;
    b1.txSetHash = sha512_256("hello");

    SECTION("compare")
    {
        Ballot b3 = b1;

        REQUIRE(!ballot::compare(b1, b3));
        REQUIRE(!ballot::compare(b3, b1));
        REQUIRE(!ballot::compareValue(b1, b3));
        REQUIRE(!ballot::compareValue(b3, b1));
        b3.baseFee++;
        REQUIRE(!ballot::compare(b1, b3));
        REQUIRE(ballot::compare(b3, b1));
        REQUIRE(!ballot::compareValue(b1, b3));
        REQUIRE(ballot::compareValue(b3, b1));
        b1.closeTime++;
        REQUIRE(ballot::compare(b1, b3));
        REQUIRE(!ballot::compare(b3, b1));
        REQUIRE(ballot::compareValue(b1, b3));
        REQUIRE(!ballot::compareValue(b3, b1));
        b3.txSetHash[0] += 1;
        REQUIRE(!ballot::compare(b1, b3));
        REQUIRE(ballot::compare(b3, b1));
        REQUIRE(!ballot::compareValue(b1, b3));
        REQUIRE(ballot::compareValue(b3, b1));

        b1.index++;
        REQUIRE(ballot::compare(b1, b3));
        REQUIRE(!ballot::compare(b3, b1));
        REQUIRE(!ballot::compareValue(b1, b3));
        REQUIRE(ballot::compareValue(b3, b1));
    }
    SECTION("isCompatible")
    {
        Ballot b3 = b1;

        REQUIRE(ballot::isCompatible(b1, b3));
        REQUIRE(ballot::isCompatible(b3, b1));
        b3.index++;
        REQUIRE(ballot::isCompatible(b1, b3));
        REQUIRE(ballot::isCompatible(b3, b1));
        b3.baseFee++;
        REQUIRE(!ballot::isCompatible(b1, b3));
        b3.baseFee--;
        b3.closeTime++;
        REQUIRE(!ballot::isCompatible(b1, b3));
        b3.closeTime--;
        b3.txSetHash[0] += 1;
        REQUIRE(!ballot::isCompatible(b1, b3));
    }
}