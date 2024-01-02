from typing_extensions import Final

from bemani.backend.base import Base, Status
from bemani.protocol import Node
from bemani.common import Time, CardCipher


class PASELIHandler(Base):
    """
    A mixin that can be used to provide PASELI services to a game.

    Handle PASELI requests. The game will check out a session at the beginning
    of the game, make PASELI purchases against that session, and then close it
    at the end of of a game. This handler ensures that this works for all games.
    """

    INFINITE_PASELI_AMOUNT: Final[int] = 57300

    """
    Override this in your subclass if the particular game/series
    needs a different padding amount to display PASELI transactions
    on the operator menu.
    """
    paseli_padding: int = 1

    def handle_eacoin_checkin_request(self, request: Node) -> Node:
        if not self.config.paseli.enabled:
            # Refuse to respond, we don't have PASELI enabled
            print("PASELI not enabled, ignoring eacoin request")
            root = Node.void("eacoin")
            root.set_attribute("status", str(Status.NOT_ALLOWED))
            return root

        root = Node.void("eacoin")
        cardid = request.child_value("cardid")
        pin = request.child_value("passwd")

        if cardid is None or pin is None:
            # Refuse to return anything
            print("Invalid eacoin checkin request, missing cardid or pin")
            root.set_attribute("status", str(Status.NO_PROFILE))
            return root

        userid = self.data.local.user.from_cardid(cardid)
        if userid is None:
            # Refuse to do anything
            print("No user for eacoin checkin request")
            root.set_attribute("status", str(Status.NO_PROFILE))
            return root

        valid = self.data.local.user.validate_pin(userid, pin)
        if not valid:
            # Refuse to do anything
            print("User entered invalid pin for eacoin checkin request")
            root.set_attribute("status", str(Status.INVALID_PIN))
            return root

        session = self.data.local.user.create_session(userid)

        if self.config.paseli.infinite:
            balance = PASELIHandler.INFINITE_PASELI_AMOUNT
        else:
            if self.config.machine.arcade is None:
                # There's no arcade for this machine, but infinite is not
                # enabled, so there's no way to find a balance.
                balance = 0
            else:
                balance = self.data.local.user.get_balance(userid, self.config.machine.arcade)

        root.add_child(Node.s16("sequence", 0))
        root.add_child(Node.u8("acstatus", 0))
        root.add_child(Node.string("acid", "DUMMY_ID"))
        root.add_child(Node.string("acname", "DUMMY_NAME"))
        root.add_child(Node.s32("balance", balance))
        root.add_child(Node.string("sessid", session))
        return root

    def handle_eacoin_opcheckin_request(self, request: Node) -> Node:
        if not self.config.paseli.enabled:
            # Refuse to respond, we don't have PASELI enabled
            print("PASELI not enabled, ignoring eacoin request")
            root = Node.void("eacoin")
            root.set_attribute("status", str(Status.NOT_ALLOWED))
            return root

        root = Node.void("eacoin")
        passwd = request.child_value("passwd")

        if passwd is None:
            # Refuse to return anything
            print("Invalid eacoin checkin request, missing passwd")
            root.set_attribute("status", str(Status.NO_PROFILE))
            return root

        if self.config.machine.arcade is None:
            # Machine doesn't belong to an arcade
            print("Machine doesn't belong to an arcade")
            root.set_attribute("status", str(Status.NO_PROFILE))
            return root

        arcade = self.data.local.machine.get_arcade(self.config.machine.arcade)
        if arcade is None:
            # Refuse to do anything
            print("No arcade for operator checkin request")
            root.set_attribute("status", str(Status.NO_PROFILE))
            return root

        if arcade.pin != passwd:
            # Refuse to do anything
            print("User entered invalid pin for operator checkin request")
            root.set_attribute("status", str(Status.INVALID_PIN))
            return root

        session = self.data.local.machine.create_session(arcade.id)
        root.add_child(Node.string("sessid", session))
        return root

    def handle_eacoin_consume_request(self, request: Node) -> Node:
        if not self.config.paseli.enabled:
            # Refuse to respond, we don't have PASELI enabled
            print("PASELI not enabled, ignoring eacoin request")
            root = Node.void("eacoin")
            root.set_attribute("status", str(Status.NOT_ALLOWED))
            return root

        def make_resp(status: int, balance: int) -> Node:
            root = Node.void("eacoin")
            root.add_child(Node.u8("acstatus", status))
            root.add_child(Node.u8("autocharge", 0))
            root.add_child(Node.s32("balance", balance))
            return root

        session = request.child_value("sessid")
        payment = request.child_value("payment")
        service = request.child_value("service")
        details = request.child_value("detail")
        if session is None or payment is None:
            # Refuse to do anything
            print("Invalid eacoin consume request, missing sessid or payment")
            return make_resp(2, 0)

        userid = self.data.local.user.from_session(session)
        if userid is None:
            # Refuse to do anything
            print("Invalid session for eacoin consume request")
            return make_resp(2, 0)

        if self.config.paseli.infinite:
            balance = PASELIHandler.INFINITE_PASELI_AMOUNT - payment
        else:
            if self.config.machine.arcade is None:
                # There's no arcade for this machine, but infinite is not
                # enabled, so there's no way to find a balance, assume failed
                # consume payment.
                balance = None
            else:
                # Look up the new balance based on this delta. If there isn't enough,
                # we will end up returning None here and exit without performing.
                balance = self.data.local.user.update_balance(userid, self.config.machine.arcade, -payment)

            if balance is None:
                print("Not enough balance for eacoin consume request")
                return make_resp(
                    1,
                    self.data.local.user.get_balance(userid, self.config.machine.arcade),
                )
            else:
                self.data.local.network.put_event(
                    "paseli_transaction",
                    {
                        "delta": -payment,
                        "balance": balance,
                        "service": -service,
                        "reason": details,
                        "pcbid": self.config.machine.pcbid,
                    },
                    userid=userid,
                    arcadeid=self.config.machine.arcade,
                )

        return make_resp(0, balance)

    def handle_eacoin_getlog_request(self, request: Node) -> Node:
        if not self.config.paseli.enabled:
            # Refuse to respond, we don't have PASELI enabled
            print("PASELI not enabled, ignoring eacoin request")
            root = Node.void("eacoin")
            root.set_attribute("status", str(Status.NOT_ALLOWED))
            return root

        root = Node.void("eacoin")
        sessid = request.child_value("sessid")
        logtype = request.child_value("logtype")
        target = request.child_value("target")
        limit = request.child_value("perpage")
        offset = request.child_value("offset")

        # Try to determine whether its a user or an arcade session
        userid = self.data.local.user.from_session(sessid)
        if userid is None:
            arcadeid = self.data.local.machine.from_session(sessid)
        else:
            arcadeid = None

        # Bail out if we don't have any idea what session this is
        if userid is None and arcadeid is None:
            print("Unable to determine session type")
            return root

        # If we're a user session, also look up the current arcade
        # so we display only entries that happened on this arcade.
        if userid is not None:
            arcade = self.data.local.machine.get_arcade(self.config.machine.arcade)
            if arcade is None:
                print("Machine doesn't belong to an arcade")
                return root
            arcadeid = arcade.id

        # Now, look up all transactions for this specific group
        events = self.data.local.network.get_events(
            userid=userid,
            arcadeid=arcadeid,
            event="paseli_transaction",
        )

        # Further filter it down to the current PCBID
        events = [event for event in events if event.data.get("pcbid") == target]

        # Grab the end of day today as a timestamp
        end_of_today = Time.end_of_today()
        time_format = "%Y-%m-%d %H:%M:%S"
        date_format = "%Y-%m-%d"

        # Set up common structure
        lognode = Node.void(logtype)
        topic = Node.void("topic")
        lognode.add_child(topic)
        summary = Node.void("summary")
        lognode.add_child(summary)

        # Display what day we are summed to
        topic.add_child(Node.string("sumdate", Time.format(Time.now(), date_format)))

        if logtype == "last7days":
            # We show today in the today total, last 7 days prior in the week total
            beginning_of_today = end_of_today - Time.SECONDS_IN_DAY
            end_of_week = beginning_of_today
            beginning_of_week = end_of_week - Time.SECONDS_IN_WEEK

            topic.add_child(Node.string("sumfrom", Time.format(beginning_of_week, date_format)))
            topic.add_child(Node.string("sumto", Time.format(end_of_week, date_format)))
            today_total = sum(
                [
                    -event.data.get_int("delta")
                    for event in events
                    if event.timestamp >= beginning_of_today and event.timestamp < end_of_today
                ]
            )

            today_total = sum(
                [
                    -event.data.get_int("delta")
                    for event in events
                    if event.timestamp >= beginning_of_today and event.timestamp < end_of_today
                ]
            )
            week_txns = [
                -event.data.get_int("delta")
                for event in events
                if event.timestamp >= beginning_of_week and event.timestamp < end_of_week
            ]
            week_total = sum(week_txns)
            if len(week_txns) > 0:
                week_avg = int(sum(week_txns) / len(week_txns))
            else:
                week_avg = 0

            # We display the totals for each day starting with yesterday and up through 7 days prior.
            # Index starts at 0 = yesterday, 1 = the day before, etc...
            items = []
            for days in range(0, 7):
                end_of_day = end_of_week - (days * Time.SECONDS_IN_DAY)
                start_of_day = end_of_day - Time.SECONDS_IN_DAY

                items.append(
                    sum(
                        [
                            -event.data.get_int("delta")
                            for event in events
                            if event.timestamp >= start_of_day and event.timestamp < end_of_day
                        ]
                    )
                )

            topic.add_child(Node.s32("today", today_total))
            topic.add_child(Node.s32("average", week_avg))
            topic.add_child(Node.s32("total", week_total))
            summary.add_child(Node.s32_array("items", items))

        if logtype == "last52weeks":
            # Start one week back, since the operator can look at last7days for newer stuff.
            beginning_of_today = end_of_today - Time.SECONDS_IN_DAY
            end_of_52_weeks = beginning_of_today - Time.SECONDS_IN_WEEK

            topic.add_child(
                Node.string(
                    "sumfrom",
                    Time.format(end_of_52_weeks - (52 * Time.SECONDS_IN_WEEK), date_format),
                )
            )
            topic.add_child(Node.string("sumto", Time.format(end_of_52_weeks, date_format)))

            # We index backwards, where index 0 = the first week back, 1 = the next week back after that, etc...
            items = []
            for weeks in range(0, 52):
                end_of_range = end_of_52_weeks - (weeks * Time.SECONDS_IN_WEEK)
                beginning_of_range = end_of_range - Time.SECONDS_IN_WEEK

                items.append(
                    sum(
                        [
                            -event.data.get_int("delta")
                            for event in events
                            if event.timestamp >= beginning_of_range and event.timestamp < end_of_range
                        ]
                    )
                )

            summary.add_child(Node.s32_array("items", items))

        if logtype == "eachday":
            start_ts = Time.now()
            end_ts = Time.now()
            weekdays = [0] * 7

            for event in events:
                event_day = Time.days_into_week(event.timestamp)
                weekdays[event_day] = weekdays[event_day] - event.data.get_int("delta")
                if event.timestamp < start_ts:
                    start_ts = event.timestamp

            topic.add_child(Node.string("sumfrom", Time.format(start_ts, date_format)))
            topic.add_child(Node.string("sumto", Time.format(end_ts, date_format)))
            summary.add_child(Node.s32_array("items", weekdays))

        if logtype == "eachhour":
            start_ts = Time.now()
            end_ts = Time.now()
            hours = [0] * 24

            for event in events:
                event_hour = int((event.timestamp % Time.SECONDS_IN_DAY) / Time.SECONDS_IN_HOUR)
                hours[event_hour] = hours[event_hour] - event.data.get_int("delta")
                if event.timestamp < start_ts:
                    start_ts = event.timestamp

            topic.add_child(Node.string("sumfrom", Time.format(start_ts, date_format)))
            topic.add_child(Node.string("sumto", Time.format(end_ts, date_format)))
            summary.add_child(Node.s32_array("items", hours))

        if logtype == "detail":
            history = Node.void("history")
            lognode.add_child(history)

            # Respect details paging
            if offset is not None:
                events = events[offset:]
            if limit is not None:
                events = events[:limit]

            # Output the details themselves
            for event in events:
                card_no = ""
                if event.userid is not None:
                    user = self.data.local.user.get_user(event.userid)
                    if user is not None:
                        cards = self.data.local.user.get_cards(user.id)
                        if len(cards) > 0:
                            card_no = CardCipher.encode(cards[0])

                item = Node.void("item")
                history.add_child(item)
                item.add_child(Node.string("date", Time.format(event.timestamp, time_format)))
                item.add_child(Node.s32("consume", -event.data.get_int("delta")))
                item.add_child(Node.s32("service", -event.data.get_int("service")))
                item.add_child(Node.string("cardtype", ""))
                item.add_child(Node.string("cardno", " " * self.paseli_padding + card_no))
                item.add_child(Node.string("title", ""))
                item.add_child(Node.string("systemid", ""))

        if logtype == "lastmonths":
            year, month, _ = Time.todays_date()
            this_month = Time.timestamp_from_date(year, month)
            last_month = Time.timestamp_from_date(year, month - 1)
            month_before = Time.timestamp_from_date(year, month - 2)

            topic.add_child(Node.string("sumfrom", Time.format(month_before, date_format)))
            topic.add_child(Node.string("sumto", Time.format(this_month, date_format)))

            for start, end in [(month_before, last_month), (last_month, this_month)]:
                year, month, _ = Time.date_from_timestamp(start)

                items = []
                for day in range(0, 31):
                    begin_ts = start + (day * Time.SECONDS_IN_DAY)
                    end_ts = begin_ts + Time.SECONDS_IN_DAY
                    if begin_ts >= end:
                        # Passed the end of this month
                        items.append(0)
                    else:
                        # Sum up all the txns for this day
                        items.append(
                            sum(
                                [
                                    -event.data.get_int("delta")
                                    for event in events
                                    if event.timestamp >= begin_ts and event.timestamp < end_ts
                                ]
                            )
                        )

                item = Node.void("item")
                summary.add_child(item)
                item.add_child(Node.s32("year", year))
                item.add_child(Node.s32("month", month))
                item.add_child(Node.s32_array("items", items))

        root.add_child(Node.u8("processing", 0))
        root.add_child(lognode)
        return root

    def handle_eacoin_opchpass_request(self, request: Node) -> Node:
        if not self.config.paseli.enabled:
            # Refuse to respond, we don't have PASELI enabled
            print("PASELI not enabled, ignoring eacoin request")
            root = Node.void("eacoin")
            root.set_attribute("status", str(Status.NOT_ALLOWED))
            return root

        root = Node.void("eacoin")
        oldpass = request.child_value("passwd")
        newpass = request.child_value("newpasswd")

        if oldpass is None or newpass is None:
            # Refuse to return anything
            print("Invalid eacoin pass change request, missing passwd")
            root.set_attribute("status", str(Status.NO_PROFILE))
            return root

        if self.config.machine.arcade is None:
            # Machine doesn't belong to an arcade
            print("Machine doesn't belong to an arcade")
            root.set_attribute("status", str(Status.NO_PROFILE))
            return root

        arcade = self.data.local.machine.get_arcade(self.config.machine.arcade)
        if arcade is None:
            # Refuse to do anything
            print("No arcade for operator pass change request")
            root.set_attribute("status", str(Status.NO_PROFILE))
            return root

        if arcade.pin != oldpass:
            # Refuse to do anything
            print("User entered invalid pin for operator pass change request")
            root.set_attribute("status", str(Status.INVALID_PIN))
            return root

        arcade.pin = newpass
        self.data.local.machine.put_arcade(arcade)
        return root

    def handle_eacoin_checkout_request(self, request: Node) -> Node:
        if not self.config.paseli.enabled:
            # Refuse to respond, we don't have PASELI enabled
            print("PASELI not enabled, ignoring eacoin request")
            root = Node.void("eacoin")
            root.set_attribute("status", str(Status.NOT_ALLOWED))
            return root

        session = request.child_value("sessid")
        if session is not None:
            # Destroy the session so it can't be used for any other purchases
            self.data.local.user.destroy_session(session)

        root = Node.void("eacoin")
        return root

    def handle_eacoin_opcheckout_request(self, request: Node) -> Node:
        if not self.config.paseli.enabled:
            # Refuse to respond, we don't have PASELI enabled
            print("PASELI not enabled, ignoring eacoin request")
            root = Node.void("eacoin")
            root.set_attribute("status", str(Status.NOT_ALLOWED))
            return root

        session = request.child_value("sessid")
        if session is not None:
            # Destroy the session so it can't be used for any other purchases
            self.data.local.machine.destroy_session(session)

        root = Node.void("eacoin")
        return root
