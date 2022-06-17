class polarian_data:
    """Module to work with polarion portal to fetch needed details"""

    from pylero.work_item import TestCase

    def extract_component_total_tc(self, config):
        """Function to fetch component-wise total testcases in all tiers."""
        component_total_tc = {}
        for component_filter_keys in config.component_filter.keys():
            for val in config.component_filter[component_filter_keys]["values"]:
                component_total_tc[str(val)] = []
                for i in config.tags:
                    query = (
                        config.component_filter[component_filter_keys]["keys"]
                        + ":"
                        + val
                        + " AND "
                        + config.key
                        + ":"
                        + str(i)
                        + " AND project.id:"
                        + config.project_id
                        + " AND "
                        "status" + ":" + "approved"
                    )
                    print(query)
                    tc = self.TestCase.get_query_result_count(query)
                    component_total_tc[str(val)].append(tc)

        return component_total_tc

    def extract_component_data(self, config):
        """Function to fetch individual component details."""
        component_data = {}
        for component_filter_keys in config.component_filter.keys():
            for val in config.component_filter[component_filter_keys]["values"]:
                component_data[str(val)] = []
                for i in config.tags:
                    query = (
                        config.component_filter[component_filter_keys]["keys"]
                        + ":"
                        + val
                        + " AND "
                        + config.key
                        + ":"
                        + str(i)
                        + " AND project.id:"
                        + config.project_id
                        + " AND caseautomation.KEY:automated"
                        + " AND "
                        "status" + ":" + "approved"
                    )
                    print(query)
                    tc = self.TestCase.get_query_result_count(query)
                    component_data[str(val)].append(tc)

        return component_data

    def extract_data(self, config):
        """Function to fetch tier-wise details"""
        print("Inside extract_data function")
        data = {}
        qury = {}
        for i in config.tags:
            data[str(i)] = []
            qury[str(i)] = []
            temp_dict = config.data[str(i)]
            for j in temp_dict.keys():
                if isinstance(temp_dict[j]["keys"], list):
                    for val in temp_dict[j]["values"][0]:
                        for val1 in temp_dict[j]["values"][1]:
                            query = (
                                temp_dict[j]["keys"][0]
                                + ":"
                                + val
                                + " AND "
                                + temp_dict[j]["keys"][1]
                                + ":"
                                + val1
                                + " AND status:approved"
                                + " AND "
                                + config.key
                                + ":"
                                + str(i)
                                + " AND project.id:"
                                + config.project_id
                            )

                            print(query)
                            tc = self.TestCase.get_query_result_count(query)
                            data[str(i)].append(tc)
                            qury[str(i)].append(query)

                else:
                    for val in temp_dict[j]["values"]:
                        query = (
                            temp_dict[j]["keys"]
                            + ":"
                            + val
                            + " AND status:approved"
                            + " AND "
                            + config.key
                            + ":"
                            + str(i)
                            + " AND project.id:"
                            + config.project_id
                        )
                        print(query)
                        tc = self.TestCase.get_query_result_count(query)
                        data[str(i)].append(tc)
                        qury[str(i)].append(query)

        return [data, qury]

    def extract_component_allstatus_data(self, config):
        """Function to fetch component-wise not-approved automated tests."""
        component_data = {}
        for component_filter_keys in config.component_filter.keys():
            for val in config.component_filter[component_filter_keys]["values"]:
                component_data[str(val)] = []
                for i in config.tags:
                    query = (
                        config.component_filter[component_filter_keys]["keys"]
                        + ":"
                        + val
                        + " AND "
                        + config.key
                        + ":"
                        + str(i)
                        + " AND project.id:"
                        + config.project_id
                        + " AND caseautomation.KEY:automated"
                        + " AND "
                        "NOT status:inactive"
                    )
                    print(query)
                    tc = self.TestCase.get_query_result_count(query)
                    component_data[str(val)].append(tc)

        return component_data

    def generate_delta_automated_all_status(
        self, config, approved_data, non_approved_data
    ):
        """
        Function to generate diff to find out the no. of tests which are automated but not in approved state.
        Args:
            config: config details from config.yaml
            approved_data : No. of tests approved and automated.
            non_approved_data: No. of tests automated and not inactive status.
        """
        print(approved_data)
        print(non_approved_data)
        comp_keys = approved_data.keys()

        diff_list = []
        for comp in comp_keys:
            for cur, prev in zip(approved_data[comp], non_approved_data[comp]):
                if cur != "":
                    diff_list.append(abs((int(cur) - int(prev))))
        print("\n Diff list :", diff_list)

        diff_dict_created = {}
        start = end = 0

        comp_details = config.component_filter["Automation"]["values"]
        for each in comp_details:
            diff_dict_created[each] = []
            end += len(config.tags)
            diff_dict_created[each] = sum(diff_list[start:end])
            start += len(config.tags)
        return diff_dict_created
