import datetime
import logging
import random
import string

import yaml

log = logging.getLogger()


def constants():
    results = []
    results.append(get_column())
    results.append(get_integer())
    results.append(get_float())
    results.append(get_string())
    results.append(get_timestamp())
    results.append(f"utcnow()")
    return results


def get_column():
    return random.choice(["_1", "_2", "_3", "_4"])


def get_integer(start=-111111111111111, end=111111111111111):
    return f"{random.randint(start, end)}"


def get_float():
    return f"{random.uniform(-111111111111111.1, 111111111111111.1)}"


def get_string():
    random_string = (
        f"{''.join(random.choices(string.ascii_letters + string.digits + ' ', k=20))}"
    )
    random_string = f"'{random_string}'"
    return random_string


def get_timestamp():
    current_date = datetime.datetime.now()
    start_date = current_date + datetime.timedelta(days=1000)
    end_date = current_date + datetime.timedelta(days=1000)
    random_date = start_date + (end_date - start_date) * random.random()
    return f"'{str(random_date.isoformat())}'"


def compare():
    results = []
    results.append(f"( expression < expression )")
    results.append(f"( expression = expression )")
    results.append(f"( expression > expression )")
    results.append(f"( expression <= expression )")
    results.append(f"( expression >= expression )")
    results.append(f"( expression != expression )")
    return results


def arithmetic():
    results = []
    results.append(f"( expression ^ expression )")
    results.append(f"( expression * expression )")
    results.append(f"( expression % expression )")
    results.append(f"( expression / expression )")
    results.append(f"( expression + expression )")
    results.append(f"( expression - expression )")
    return results


def logical():
    results = []
    results.append(f"true")
    results.append(f"false")
    results.append(f"( expression and expression )")
    results.append(f"( expression or expression )")
    results.append(f"( not expression )")
    results.append(f"( expression is null )")
    results.append(f"( expression is not null )")
    results.append(f"null")
    return results


def case():
    results = []
    results.append(
        f"case expression when expression then expression else expression end"
    )
    results.append(f"case when expression then expression else expression end")
    return results


def cast_operator():
    results = []
    results.append(f"cast( expression as int)")
    results.append(f"cast( expression as float)")
    results.append(f"cast( expression as string)")
    results.append(f"cast( expression as bool)")
    results.append(f"cast( expression as timestamp)")
    return results


def non_aws_cast_operator():
    results = []
    results.append(f"int( expression )")
    results.append(f"float( expression )")
    results.append(f"string( expression )")
    results.append(f"to_timestamp( expression )")
    return results


def coalesce():
    results = []
    results.append(f"coalesce ( expression , expression )")
    return results


def nullif():
    results = []
    results.append(f"nullif ( expression , expression )")
    return results


def in_operator():
    results = []
    results.append(f"(expression in ( expression , expression ))")
    return results


def between_operator():
    results = []
    results.append(f"(expression between expression and expression )")
    return results


def like_operator():
    results = []
    results.append(f"(expression like expression)")
    return results


def aggregation():
    # only applicable to select clause
    results = []
    results.append(f"sum( expression )")
    results.append(f"avg( expression )")
    results.append(f"min( expression )")
    results.append(f"max( expression )")
    results.append(f"count( expression )")
    return results


# string functions


def trim():
    results = []
    results.append(f"trim( expression )")
    results.append(f"trim( trailing expression from expression )")
    results.append(f"trim( leading expression from expression )")
    results.append(f"trim( both expression from expression )")
    return results


def char_length():
    results = []
    results.append(f"char_length( expression )")
    results.append(f"character_length( expression )")
    return results


def substring():
    results = []
    results.append(f"substring( expression )")
    results.append(f"substring( expression , expression )")
    results.append(f"substring( expression , expression , expression )")
    return results


def upper_lower():
    results = []
    results.append(f"upper( expression )")
    results.append(f"lower( expression )")
    return results


# timestamp functions


def to_timestamp():
    results = []
    results.append(f"to_timestamp( expression )")
    return results


def extract():
    results = []
    date_parts = [
        "year",
        "month",
        "week",
        "day",
        "hour",
        "minute",
        "second",
        "timezone_hour",
        "timezone_minute",
    ]
    for date_part in date_parts:
        results.append(f"extract( {date_part} from expression )")
    return results


def date_add():
    results = []
    date_parts = ["year", "month", "day", "hour", "minute", "second"]
    for date_part in date_parts:
        results.append(f"date_add( {date_part} , expression , expression )")
    return results


def date_diff():
    results = []
    date_parts = ["year", "month", "day", "hour", "minute", "second"]
    for date_part in date_parts:
        results.append(f"date_diff( {date_part} , expression , expression )")
    return results


def utcnow():
    results = []
    results.append(f"utcnow()")
    return results


def to_string():
    results = []
    formats = [
        "yy",
        "y",
        "yyyy",
        "M",
        "MM",
        "MMM",
        "MMMM",
        "MMMMM",
        "d",
        "dd",
        "a",
        "h",
        "hh",
        "H",
        "HH",
        "m",
        "mm",
        "s",
        "ss",
        "S",
        "SS",
        "SSS",
        "SSSSS",
        "n",
        "X",
        "XX",
        "XXXX",
        "XXX",
        "XXXXX",
        "x",
        "xx",
        "xxxx",
        "xxx",
        "xxxxx",
    ]
    for fmt in formats:
        results.append(f"to_string( expression ,  {fmt})")
    return results


def multivalued_features_sample_queries():
    results = []
    results.append(random.choice(to_string()))
    results.append(random.choice(extract()))
    results.append(random.choice(date_add()))
    results.append(random.choice(date_diff()))
    results.append(random.choice(to_string()))
    return results


# Generate queries


def gen_query(depth):
    constants_methods_list = [
        get_column,
        get_integer,
        get_float,
        get_string,
        get_timestamp,
    ]
    expression_templates = (
        compare()
        + arithmetic()
        + logical()
        + case()
        + cast_operator()
        + non_aws_cast_operator()
        + coalesce()
        + nullif()
        + in_operator()
        + between_operator()
        + like_operator()
        + aggregation()
        + trim()
        + char_length()
        + substring()
        + upper_lower()
        + to_timestamp()
    )

    if depth == 1:
        depth1_templates = (
            expression_templates + to_string() + extract() + date_add() + date_diff()
        )
        results = []
        for exp in depth1_templates:
            # new_exp = exp.replace("expression", "constant")
            new_exp = exp
            queue1 = [new_exp]
            exp_count = new_exp.count("expression")
            for exp_index in range(exp_count):
                queue2 = []
                for intermediate_exp in queue1:
                    for method in constants_methods_list:
                        queue2.append(
                            intermediate_exp.replace("expression", method(), 1)
                        )
                queue1 = queue2
            results.extend(queue1)
    else:
        results = ["expression"]
        while depth > 0:
            queue = []
            for exp in results:
                if "expression" in exp:
                    # shuffling the templates and for every template replacing 'expression' with it
                    templates = (
                        expression_templates + multivalued_features_sample_queries()
                    )
                    templates_len = len(templates)
                    random.shuffle(templates)
                    exp_count = exp.count("expression")
                    for template_index in range(templates_len):
                        arr = exp.split("expression")
                        index = 1
                        count = 0
                        while count < exp_count:
                            arr.insert(
                                index,
                                templates[(template_index + count) % templates_len],
                            )
                            count = count + 1
                            index = index + 2
                        new_exp = "".join(arr)
                        queue.append(new_exp)
                else:
                    queue.append(exp)
            depth = depth - 1
            results = queue

        for index in range(len(results)):
            exp_count = results[index].count("expression")
            for _ in range(exp_count):
                results[index] = results[index].replace(
                    "expression", random.choice(constants()), 1
                )
    return results


def get_queries(s3_object_name, s3_object_path, depth, s3_queries_path):
    log.info(f"Generating queries for all features with depth {depth}..\n")
    expressions = gen_query(depth)
    queries = []
    for exp in expressions:
        queries.append(f"select {exp} from s3object;")

    yaml_data = {
        "s3_object_name": s3_object_name,
        "s3_object_path": s3_object_path,
        "queries": [],
    }
    log.info(f"Number of queries generated: {len(queries)}\n")
    for index in range(len(queries)):
        element = {"id": index, "query": queries[index], "result": ""}
        log.info(f"{index + 1}. {queries[index]}")
        yaml_data["queries"].append(element)

    # writing queries to yaml file
    log.info(f"\nwriting queries to yaml file: {s3_queries_path}")
    with open(s3_queries_path, "w") as yaml_file:
        yaml_file.write(yaml.dump(yaml_data, default_flow_style=False))
    return yaml_data
